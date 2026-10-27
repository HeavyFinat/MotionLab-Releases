import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {LIMITS,validatePackage,validatePng,sha256,PolicyError} from './PackagePolicy.mjs';
import {publication,item,text,idValid,RULES_VERSION} from './MarketMetadata.mjs';

export const GITHUB_LIMITS=Object.freeze({submissionBytes:15*1024*1024,catalogBytes:1024*1024,items:200,totalBytes:200*1024*1024});
function check(ok,message){if(!ok)throw new PolicyError(message);}
export function githubLogin(value){
  check(typeof value==='string'&&/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value)&&!value.includes('--'),'Некорректное имя пользователя GitHub.');
  return value.toLowerCase();
}
export function githubAuthorId(login){
  const h=createHash('sha256').update('motionlab-github:'+githubLogin(login)).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-4${h.slice(13,16)}-8${h.slice(17,20)}-${h.slice(20,32)}`;
}
function decodeFile(value,max,label){
  check(value&&Number.isSafeInteger(value.bytes)&&value.bytes>0&&value.bytes<=max
    &&typeof value.base64==='string'&&value.base64.length<=Math.ceil(max/3)*4
    &&/^[A-Za-z0-9+/]*={0,2}$/.test(value.base64)&&value.base64.length%4===0
    &&typeof value.sha256==='string'&&/^[a-f0-9]{64}$/.test(value.sha256),`${label}: некорректный размер или формат.`);
  const data=Buffer.from(value.base64,'base64');
  check(data.length===value.bytes&&data.toString('base64')===value.base64&&sha256(data)===value.sha256,`${label}: размер или SHA-256 не совпадает.`);
  return data;
}
export function validateSubmission(input){
  const bytes=Buffer.from(input);check(bytes.length>0&&bytes.length<=GITHUB_LIMITS.submissionBytes,'Заявка больше 15 МиБ.');
  let envelope;try{envelope=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new PolicyError('Повреждённый JSON заявки.');}
  check(envelope?.schema_version===1&&Object.keys(envelope).every(k=>['schema_version','metadata','package','preview'].includes(k)),'Неизвестная схема заявки.');
  const meta=publication(envelope.metadata),nick=text(envelope.metadata.nick,2,24,'Ник');
  const packageData=decodeFile(envelope.package,LIMITS.packageBytes,'Пакет'),previewData=decodeFile(envelope.preview,LIMITS.previewBytes,'Превью');
  const checked=validatePackage(packageData,envelope.package.extension);validatePng(previewData,LIMITS.previewBytes);
  return {meta:{...meta,nick},packageData,previewData,extension:checked.extension,packageSha:checked.sha256,previewSha:sha256(previewData)};
}
export function createSubmission(meta,nick,packageData,extension,previewData){
  const part=(bytes,extra={})=>({bytes:bytes.length,sha256:sha256(bytes),base64:Buffer.from(bytes).toString('base64'),...extra});
  const bytes=Buffer.from(JSON.stringify({schema_version:1,metadata:{...publication(meta),nick:text(nick,2,24,'Ник')},package:part(packageData,{extension}),preview:part(previewData)}));
  validateSubmission(bytes);return bytes;
}
export function publicationRecord(checked,identity){
  const login=githubLogin(identity.login);check(Number.isSafeInteger(identity.pr)&&identity.pr>0,'Некорректный номер Pull Request.');
  check(typeof identity.createdAt==='string'&&Number.isFinite(Date.parse(identity.createdAt)),'Неизвестна дата подачи заявки.');
  const m=checked.meta;
  return {id:m.requestId,author_id:githubAuthorId(login),author_nick:m.nick,title:m.title,description:m.description,category:m.category,tags:m.tags,license:m.license,
    extension:checked.extension,package_bytes:checked.packageData.length,package_sha256:checked.packageSha,preview_bytes:checked.previewData.length,preview_sha256:checked.previewSha,
    status:'published',created_at:identity.createdAt,downloads:null,github_login:login,source_pr:identity.pr,popularity:Math.min(1000000,Math.max(0,Number.isSafeInteger(identity.popularity)?identity.popularity:0)),
    package_path:`marketplace/packages/${m.requestId}.${checked.extension}`,preview_path:`marketplace/previews/${m.requestId}.png`};
}
export function githubItem(raw){
  check(raw?.downloads===null,'GitHub не предоставляет точный счётчик скачиваний raw-файлов.');
  const login=githubLogin(raw.github_login);
  check(raw.author_id===githubAuthorId(login)&&Number.isSafeInteger(raw.source_pr)&&raw.source_pr>0
    &&Number.isSafeInteger(raw.popularity)&&raw.popularity>=0&&raw.popularity<=1000000
    &&raw.package_path===`marketplace/packages/${raw.id}.${raw.extension}`&&raw.preview_path===`marketplace/previews/${raw.id}.png`,'Некорректные параметры публикации GitHub.');
  return {...item({...raw,downloads:0}),downloads:null,popularity:raw.popularity,githubLogin:login,sourcePr:raw.source_pr};
}
export function validateCatalog(value){
  check(value?.schema_version===1&&value.rules_version===RULES_VERSION&&Array.isArray(value.items)&&value.items.length<=GITHUB_LIMITS.items,'Некорректный каталог GitHub.');
  check(typeof value.updated_at==='string'&&Number.isFinite(Date.parse(value.updated_at)),'Некорректная дата каталога.');
  const ids=new Set();let total=0;
  for(const raw of value.items){githubItem(raw);check(!ids.has(raw.id),'Повторяющиеся публикации.');ids.add(raw.id);total+=raw.package_bytes+raw.preview_bytes;}
  check(total<=GITHUB_LIMITS.totalBytes,'Каталог превышает лимит пилотного маркета.');return value;
}
export function moderation(value){
  check(value?.schema_version===1&&Array.isArray(value.hidden)&&Array.isArray(value.deleted)&&Array.isArray(value.banned_authors),'Некорректный файл модерации.');
  check(value.hidden.length<=1000&&value.deleted.length<=1000&&value.banned_authors.length<=1000
    &&[...value.hidden,...value.deleted].every(idValid),'Некорректные номера публикаций в модерации.');
  return {schema_version:1,hidden:[...new Set(value.hidden)],deleted:[...new Set(value.deleted)],banned_authors:[...new Set(value.banned_authors.map(githubLogin))]};
}
