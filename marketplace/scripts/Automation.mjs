import fs from 'node:fs/promises';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {validateSubmission,publicationRecord,validateCatalog,moderation,githubLogin,GITHUB_LIMITS} from './GitHubSchema.mjs';
import {idValid,RULES_VERSION} from './MarketMetadata.mjs';

const fail=(message)=>{throw new Error(message);};
export async function bounded(response,max){
  const length=response.headers.get('content-length');if(length&&(!/^\d+$/.test(length)||Number(length)>max)){await response.body?.cancel();fail('Ответ GitHub больше лимита.');}
  if(!response.body)fail('Пустой ответ GitHub.');const reader=response.body.getReader(),chunks=[];let size=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>max)fail('Превышен лимит ответа.');chunks.push(Buffer.from(value));}}
  catch(e){await reader.cancel().catch(()=>{});throw e;}finally{reader.releaseLock();}return Buffer.concat(chunks,size);
}
export function githubService({repository,token,fetcher=fetch}){
  if(!/^[-A-Za-z0-9_]+\/[A-Za-z0-9_.-]+$/.test(repository)||repository.includes('..'))fail('Неизвестный репозиторий.');
  const api=async(route)=>{
    if(!route.startsWith(`/repos/${repository}/`))fail('Недопустимый запрос API.');
    const response=await fetcher('https://api.github.com'+route,{headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(token?{Authorization:`Bearer ${token}`}:{})},redirect:'error',signal:AbortSignal.timeout(25000)});
    if(!response.ok){await response.body?.cancel();fail('GitHub API недоступен: HTTP '+response.status);}
    return JSON.parse((await bounded(response,4*1024*1024)).toString('utf8'));
  };
  const raw=async(repo,commit,file)=>{
    if(!/^[-A-Za-z0-9_]+\/[A-Za-z0-9_.-]+$/.test(repo)||repo.includes('..')||!/^[a-f0-9]{40}$/.test(commit)
      ||!/^marketplace\/submissions\/[a-f0-9-]{36}\.json$/.test(file))fail('Недопустимый путь заявки.');
    const response=await fetcher(`https://raw.githubusercontent.com/${repo}/${commit}/${file}`,{redirect:'error',signal:AbortSignal.timeout(30000)});
    if(!response.ok){await response.body?.cancel();fail('Не удалось получить заявку.');}return bounded(response,GITHUB_LIMITS.submissionBytes);
  };
  return {api,raw,repository};
}
export function submissionPath(file){return typeof file==='string'&&/^marketplace\/submissions\/[a-f0-9-]{36}\.json$/.test(file)&&idValid(path.posix.basename(file,'.json'));}
export function onlySubmission(files){
  if(!Array.isArray(files)||files.length!==1||files[0].status!=='added'||!submissionPath(files[0].filename)||!/^[a-f0-9]{40}$/.test(files[0].sha))fail('Заявка должна только добавлять один JSON в marketplace/submissions. Изменения кода и других файлов запрещены.');return files[0];
}
const blobSha=data=>createHash('sha1').update(Buffer.from(`blob ${data.length}\0`)).update(data).digest('hex');
export async function verifyPr(service,number,{bytes=null,requireMerged=false,expectedPath=null}={}){
  if(!Number.isSafeInteger(number)||number<1)fail('Некорректный номер PR.');
  const pr=await service.api(`/repos/${service.repository}/pulls/${number}`);
  if(pr.base?.repo?.full_name?.toLowerCase()!==service.repository.toLowerCase()||pr.base.ref!=='main'||pr.changed_files!==1||requireMerged&&!pr.merged_at)fail('Неизвестная или не одобренная заявка.');
  const file=onlySubmission(await service.api(`/repos/${service.repository}/pulls/${number}/files?per_page=100`));
  if(expectedPath&&file.filename!==expectedPath)fail('Pull Request не относится к этому пакету.');
  if(!bytes)bytes=await service.raw(pr.head.repo.full_name,pr.head.sha,file.filename);
  if(blobSha(bytes)!==file.sha)fail('Содержимое заявки не совпадает с одобренным Pull Request.');
  const checked=validateSubmission(bytes);
  if(path.posix.basename(file.filename,'.json')!==checked.meta.requestId)fail('UUID файла и заявки не совпадает.');
  return {pr,checked,identity:{login:githubLogin(pr.user.login),pr:number,createdAt:pr.created_at,popularity:0}};
}
export async function dailyQuota(service,pr){
  const login=githubLogin(pr.user.login),day=pr.created_at.slice(0,10);let count=0,done=false;
  for(let page=1;page<=10&&!done;page++){
    const list=await service.api(`/repos/${service.repository}/pulls?state=all&sort=created&direction=desc&per_page=100&page=${page}`);
    if(!Array.isArray(list))fail('Не удалось проверить ограничение заявок.');
    for(const x of list){if(x.created_at.slice(0,10)<day){done=true;break;}if(x.created_at.slice(0,10)===day&&githubLogin(x.user.login)===login)count++;}
    if(list.length<100)done=true;
  }
  if(!done)fail('Слишком много заявок для безопасной проверки дневного лимита.');
  if(count>3)fail('Допускается не больше трёх новых Pull Request за день по UTC.');
}
export function checkCatalogueQuota(records,mod){
  const authors=new Map(),days=new Map();let total=0;
  for(const r of records){
    const key=r.github_login+':'+r.created_at.slice(0,10);days.set(key,(days.get(key)||0)+1);if(days.get(key)>3)fail('Превышено три принятых заявки автора за день по UTC.');
    total+=r.package_bytes+r.preview_bytes;
    if(!mod.deleted.includes(r.id)){authors.set(r.github_login,(authors.get(r.github_login)||0)+1);if(authors.get(r.github_login)>10)fail('У автора больше 10 активных публикаций.');}
  }
  if(records.length>200||total>GITHUB_LIMITS.totalBytes)fail('Пилотный каталог превышает лимит 200 работ / 200 МиБ.');
}
export async function quotaRecords(root){
  const manifest=JSON.parse(await fs.readFile(path.join(root,'marketplace/owners.json'),'utf8'));
  if(manifest?.schema_version!==1||!Array.isArray(manifest.owners)||manifest.owners.length>200)fail('Некорректный реестр принятых заявок.');
  const names=(await fs.readdir(path.join(root,'marketplace/submissions'))).filter(x=>x!=='README.md');
  const ids=new Set();
  const records=manifest.owners.map(x=>{
    if(!idValid(x.id)||ids.has(x.id)||!Number.isSafeInteger(x.source_pr)||x.source_pr<1
      ||typeof x.created_at!=='string'||x.created_at.length>40||!Number.isFinite(Date.parse(x.created_at))
      ||!Number.isSafeInteger(x.package_bytes)||x.package_bytes<1||x.package_bytes>10*1024*1024
      ||!Number.isSafeInteger(x.preview_bytes)||x.preview_bytes<1||x.preview_bytes>512*1024)fail('Некорректные квоты реестра принятых заявок.');
    ids.add(x.id);return {id:x.id,github_login:githubLogin(x.login),created_at:x.created_at,package_bytes:x.package_bytes,preview_bytes:x.preview_bytes};
  });
  if(names.length!==ids.size||names.some(x=>!submissionPath('marketplace/submissions/'+x)||!ids.has(path.basename(x,'.json'))))
    fail('Дождитесь успешного обновления каталога после предыдущего слияния и повторите проверку PR.');
  return records;
}
export async function validatePullRequest(service,number,root='.'){
  const mod=moderation(JSON.parse(await fs.readFile(path.join(root,'marketplace/moderation.json'),'utf8')));
  const {pr,checked,identity}=await verifyPr(service,number);await dailyQuota(service,pr);
  if(mod.banned_authors.includes(identity.login))fail('Автор заблокирован владельцем маркета.');
  const records=await quotaRecords(root);
  if(records.some(x=>x.id===checked.meta.requestId))fail('Этот номер публикации уже существует.');
  checkCatalogueQuota([...records,publicationRecord(checked,identity)],mod);
  return {id:checked.meta.requestId,login:identity.login};
}
export async function compileCatalog(service,root='.',{proofForFile}={}){
  const mod=moderation(JSON.parse(await fs.readFile(path.join(root,'marketplace/moderation.json'),'utf8')));
  const base=path.join(root,'marketplace'),source=path.join(base,'submissions'),records=[],packages=[];
  for(const name of (await fs.readdir(source)).sort()){
    if(name==='README.md')continue;if(!submissionPath('marketplace/submissions/'+name))fail('Неизвестный файл в submissions.');
    const file='marketplace/submissions/'+name,full=path.join(root,...file.split('/')),stat=await fs.lstat(full);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.size>GITHUB_LIMITS.submissionBytes)fail('Некорректный файл заявки.');
    const bytes=await fs.readFile(full);let proof;
    if(proofForFile)proof=await proofForFile(file,bytes);
    else{
      const commit=execFileSync('git',['log','--diff-filter=A','--format=%H','-n','1','--',file],{cwd:root,encoding:'utf8'}).trim();
      if(!/^[a-f0-9]{40}$/.test(commit))fail('Не найдена история заявки.');
      const associated=await service.api(`/repos/${service.repository}/commits/${commit}/pulls?per_page=100`);
      const merged=associated.filter(p=>p.merged_at&&p.base?.repo?.full_name?.toLowerCase()===service.repository.toLowerCase()&&p.base.ref==='main');
      if(merged.length!==1)fail('Для заявки нужен один одобренный Pull Request. Прямая запись в main не публикует работу.');
      proof=await verifyPr(service,merged[0].number,{bytes,requireMerged:true,expectedPath:file});
    }
    if(!proof?.checked||proof.checked.meta.requestId!==path.basename(name,'.json'))fail('Подтверждение PR не совпадает с заявкой.');
    let popularity=0;
    if(!proofForFile){const issue=await service.api(`/repos/${service.repository}/issues/${proof.identity.pr}`);const reactions=issue.reactions||{};popularity=['+1','heart','hooray','rocket'].reduce((n,k)=>n+(Number.isSafeInteger(reactions[k])?reactions[k]:0),0);}
    const record=publicationRecord(proof.checked,{...proof.identity,popularity});checkCatalogueQuota([...records,record],mod);records.push(record);packages.push({record,checked:proof.checked});
  }
  checkCatalogueQuota(records,mod);
  const visible=records.filter(r=>!mod.hidden.includes(r.id)&&!mod.deleted.includes(r.id)&&!mod.banned_authors.includes(r.github_login));
  const catalogue=validateCatalog({schema_version:1,rules_version:RULES_VERSION,updated_at:new Date().toISOString(),items:visible});
  for(const folder of ['packages','previews']){await fs.rm(path.join(base,folder),{recursive:true,force:true});await fs.mkdir(path.join(base,folder),{recursive:true});}
  await fs.writeFile(path.join(base,'packages','README.md'),'Проверенные файлы. Каталог обновляется автоматически после одобрения PR.\n');
  await fs.writeFile(path.join(base,'previews','README.md'),'Проверенные PNG-превью публикаций.\n');
  const visibleIds=new Set(visible.map(x=>x.id));
  for(const {record:r,checked:c}of packages)if(visibleIds.has(r.id)){
    await fs.writeFile(path.join(root,...r.package_path.split('/')),c.packageData,{mode:0o644});
    await fs.writeFile(path.join(root,...r.preview_path.split('/')),c.previewData,{mode:0o644});
  }
  const owners={schema_version:1,owners:records.map(r=>({id:r.id,login:r.github_login,source_pr:r.source_pr,created_at:r.created_at,package_bytes:r.package_bytes,preview_bytes:r.preview_bytes}))};
  await fs.writeFile(path.join(base,'catalog.json'),JSON.stringify(catalogue,null,2)+'\n');
  await fs.writeFile(path.join(base,'owners.json'),JSON.stringify(owners,null,2)+'\n');return catalogue;
}
export function authorizeRemoval(issue,owners,repository){
  if(!issue||issue.pull_request||issue.title?.startsWith('[Маркет: удалить] ')!==true)return null;
  const match=String(issue.body||'').match(/### Идентификатор публикации\s+([a-f0-9-]{36})(?:\s|$)/);
  if(!match||!idValid(match[1])||issue.title!==`[Маркет: удалить] ${match[1]}`)fail('Неизвестный номер публикации.');
  if(owners?.schema_version!==1||!Array.isArray(owners.owners))fail('Неизвестен автор публикации.');
  const item=owners.owners.find(x=>x.id===match[1]);if(!item)fail('Публикация не найдена.');
  const login=githubLogin(issue.user?.login),owner=githubLogin(repository.split('/')[0]);
  if(login!==githubLogin(item.login)&&login!==owner)fail('Удалять публикацию может её автор или владелец репозитория.');return item.id;
}
