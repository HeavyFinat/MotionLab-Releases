// Shared input/record schema for both sides of the market.
export const CATEGORIES=Object.freeze({presets:'Пресеты',settings:'Наборы настроек'});
export const LICENSES=Object.freeze({'CC0-1.0':'CC0 — без условий','CC-BY-4.0':'CC BY — с указанием автора','CC-BY-NC-4.0':'CC BY-NC — без коммерческого использования'});
export const RULES_VERSION='2026-10-27.2';
export const idValid=id=>typeof id==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id);
function assert(ok,message='Некорректные данные публикации.') {if(!ok){const e=new Error(message);e.code='BAD_REQUEST';throw e;}}
export function text(value,min,max,label='Текст') {
  assert(typeof value==='string',`${label}: введите текст.`);const result=value.trim();
  assert(result.length>=min&&result.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(result),`${label}: от ${min} до ${max} символов, без управляющих знаков.`);return result;
}
export function tags(value) {
  assert(Array.isArray(value)&&value.length<=5,'Допускается не больше 5 тегов.');
  const result=value.map(x=>text(x,1,24,'Тег').toLowerCase());
  assert(result.every(x=>/^[\p{L}\p{N}_-]+$/u.test(x))&&new Set(result).size===result.length,'Теги: буквы, цифры, _, -, без повторов.');return result;
}
export function publication(value) {
  assert(value&&idValid(value.requestId));
  assert(Object.hasOwn(CATEGORIES,value.category)&&Object.hasOwn(LICENSES,value.license));
  assert(value.rightsConfirmed===true&&value.rulesVersion===RULES_VERSION,'Подтвердите права и текущие правила маркета.');
  return {requestId:value.requestId,title:text(value.title,3,80,'Название'),description:text(value.description,10,2000,'Описание'),
    category:value.category,tags:tags(value.tags),license:value.license,rightsConfirmed:true,rulesVersion:RULES_VERSION};
}
export function item(value,allowPrivate=false) {
  assert(value&&idValid(value.id)&&idValid(value.author_id));
  assert((allowPrivate?['pending','published','hidden','deleted']:['published']).includes(value.status));
  assert(Object.hasOwn(CATEGORIES,value.category)&&Object.hasOwn(LICENSES,value.license));
  assert(['json','png','zip'].includes(value.extension)&&Number.isSafeInteger(value.package_bytes)&&value.package_bytes>0&&value.package_bytes<=10*1024*1024
    &&Number.isSafeInteger(value.preview_bytes)&&value.preview_bytes>0&&value.preview_bytes<=512*1024
    &&/^[a-f0-9]{64}$/.test(value.package_sha256)&&/^[a-f0-9]{64}$/.test(value.preview_sha256));
  assert(Number.isSafeInteger(value.downloads)&&value.downloads>=0&&value.downloads<=1e9);
  assert(typeof value.created_at==='string'&&Number.isFinite(Date.parse(value.created_at))&&value.created_at.length<=40);
  return {id:value.id,authorId:value.author_id,author:text(value.author_nick,2,24,'Ник'),title:text(value.title,3,80,'Название'),
    description:text(value.description,10,2000,'Описание'),category:value.category,tags:tags(value.tags),license:value.license,status:value.status,
    extension:value.extension,bytes:value.package_bytes,sha256:value.package_sha256,previewBytes:value.preview_bytes,previewSha256:value.preview_sha256,
    downloads:value.downloads,createdAt:value.created_at};
}
export function query(value={}) {
  const result={q:text(value.q??'',0,80,'Поиск'),category:value.category||'',tag:text(value.tag??'',0,24,'Тег'),
    sort:value.sort||'new',page:value.page??0};
  assert(result.category===''||Object.hasOwn(CATEGORIES,result.category));
  assert(['new','popular'].includes(result.sort)&&Number.isSafeInteger(result.page)&&result.page>=0&&result.page<=1000);
  if(result.tag)tags([result.tag]);return result;
}
