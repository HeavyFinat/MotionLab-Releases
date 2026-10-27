import fs from 'node:fs/promises';
import {githubService,validatePullRequest,compileCatalog,authorizeRemoval} from './Automation.mjs';
import {moderation} from './GitHubSchema.mjs';

const service=githubService({repository:process.env.GITHUB_REPOSITORY,token:process.env.GITHUB_TOKEN});
const mode=process.argv[2];
if(mode==='validate-pr'){
  const event=JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH,'utf8'));
  await validatePullRequest(service,event.pull_request?.number);console.log('MARKET_SUBMISSION_VALID');
}else if(mode==='build'){
  await compileCatalog(service);console.log('MARKET_CATALOG_BUILT');
}else if(mode==='remove'){
  const event=JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH,'utf8'));
  const owners=JSON.parse(await fs.readFile('marketplace/owners.json','utf8'));
  const id=authorizeRemoval(event.issue,owners,service.repository);
  if(id){const file='marketplace/moderation.json',mod=moderation(JSON.parse(await fs.readFile(file,'utf8')));if(!mod.deleted.includes(id))mod.deleted.push(id);await fs.writeFile(file,JSON.stringify(mod,null,2)+'\n');await compileCatalog(service);console.log('MARKET_PUBLICATION_REMOVED_FROM_CATALOG');}
}else throw Error('Неизвестный режим.');
