// Canonical policy, bundled unchanged into the desktop and the Edge Function.
// This module never executes package data.
import { inflateRawSync, inflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

export const LIMITS = Object.freeze({
  packageBytes: 10 * 1024 * 1024, expandedBytes: 32 * 1024 * 1024,
  fileBytes: 2 * 1024 * 1024, previewBytes: 512 * 1024,
  entries: 128, ratio: 100, pixels: 2048 * 2048, side: 2048,
  rulesVersion: '2026-10-27.2',
});
export class PolicyError extends Error {
  constructor(message) { super(message); this.code = 'INVALID_PACKAGE'; }
}
function check(ok, message) { if (!ok) throw new PolicyError(message); }
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const CRC_TABLE=Uint32Array.from({length:256},(_,value)=>{let n=value;for(let i=0;i<8;i++)n=(n>>>1)^((n&1)?0xedb88320:0);return n>>>0;});
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const b of bytes) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ b) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}
export function safeName(name, directory = false) {
  check(typeof name === 'string' && name.length > 0 && name.length <= 160,
    'Слишком длинное или пустое имя файла.');
  const value = directory && name.endsWith('/') ? name.slice(0, -1) : name;
  const parts = value.split('/');
  check(parts.length <= 6 && parts.every(p => /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/.test(p)
    && !p.endsWith('.') && !p.includes('..')
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)),
  'Недопустимый путь. Используйте латинские буквы, цифры, _, - и обычные папки, без ../ и системных имён.');
  if (!directory) check(/\.(json|png)$/i.test(value),
    'Разрешены только JSON и PNG. Исполняемые файлы, скрипты и вложенные архивы запрещены.');
  return value;
}

export function validateJson(bytes, budget = null) {
  check(bytes.length > 0 && bytes.length <= LIMITS.fileBytes, 'JSON должен быть не больше 2 МиБ.');
  let data;
  try { data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new PolicyError('Файл содержит повреждённый JSON.'); }
  check(data && !Array.isArray(data) && typeof data === 'object'
    && data.motionlab_market === 1 && ['preset', 'settings'].includes(data.kind)
    && data.values && typeof data.values === 'object' && !Array.isArray(data.values)
    && Object.keys(data).every(k => ['motionlab_market', 'kind', 'values'].includes(k)),
  'Нужен JSON MotionLab: motionlab_market: 1, kind: preset или settings, values: объект настроек.');
  let nodes = 0;
  function walk(value, depth) {
    check(++nodes <= 5000 && depth <= 8, 'Слишком сложная структура JSON.');
    if(budget){budget.jsonNodes++;check(budget.jsonNodes<=20000,'Слишком много значений настроек в одном пакете.');}
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'number') { check(Number.isFinite(value) && Math.abs(value) <= 1e9, 'Некорректное число в JSON.'); return; }
    if (typeof value === 'string') { check(value.length <= 2000 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value), 'Некорректный текст в JSON.'); return; }
    check(typeof value === 'object', 'Недопустимое значение JSON.');
    for (const [key, child] of Object.entries(value)) {
      check(/^[A-Za-z0-9_-]{1,64}$/.test(key)
        && !/^(?:__proto__|prototype|constructor|script|expression|code|eval|command)$/i.test(key),
      'JSON содержит запрещённое поле. Код, команды и expressions не поддерживаются.');
      walk(child, depth + 1);
    }
  }
  walk(data.values, 0);
  return data;
}

export function validatePng(input, maxBytes = LIMITS.fileBytes, budget = null) {
  const b = Buffer.from(input);
  check(b.length >= 45 && b.length <= maxBytes
    && b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])), 'Нужен корректный PNG допустимого размера.');
  let pos = 8, width = 0, height = 0, channels = 0, ended = false, idatEnded = false;
  const chunks = [];
  let chunkCount = 0, hasPalette = false, colorType = -1;
  const allowed = new Set(['IHDR', 'PLTE', 'tRNS', 'IDAT', 'IEND', 'sRGB', 'gAMA', 'cHRM', 'pHYs']);
  while (pos + 12 <= b.length) {
    check(++chunkCount <= 2048, 'Слишком много блоков PNG.');
    const size = b.readUInt32BE(pos), type = b.toString('ascii', pos + 4, pos + 8);
    check(size <= maxBytes && pos + 12 + size <= b.length && allowed.has(type), 'Повреждённый PNG или неподдерживаемые метаданные.');
    check(crc32(b.subarray(pos + 4, pos + 8 + size)) === b.readUInt32BE(pos + 8 + size), 'Повреждённая контрольная сумма PNG.');
    if (type === 'IHDR') {
      check(pos === 8 && size === 13, 'Некорректный заголовок PNG.');
      width = b.readUInt32BE(pos + 8); height = b.readUInt32BE(pos + 12);
      colorType = b[pos + 17]; channels = ({0:1,2:3,3:1,4:2,6:4})[colorType];
      check(width > 0 && height > 0 && width <= LIMITS.side && height <= LIMITS.side
        && width * height <= LIMITS.pixels && b[pos + 16] === 8 && channels
        && b[pos + 18] === 0 && b[pos + 19] === 0 && b[pos + 20] === 0,
      'PNG: максимум 2048×2048, 8 бит, без чересстрочной развёртки. Пересохраните изображение.');
    } else check(width > 0, 'PNG начинается не с IHDR.');
    if (type === 'PLTE') { check(!chunks.length && !hasPalette && size > 0 && size <= 768 && size % 3 === 0, 'Некорректная палитра PNG.'); hasPalette = true; }
    if (type === 'IDAT') { check(!idatEnded && (colorType !== 3 || hasPalette), 'Некорректный порядок PNG.'); chunks.push(b.subarray(pos + 8, pos + 8 + size)); }
    else if (chunks.length) idatEnded = true;
    pos += 12 + size;
    if (type === 'IEND') { check(size === 0 && pos === b.length && chunks.length > 0, 'Лишние данные или пустой PNG.'); ended = true; break; }
  }
  check(ended, 'PNG не завершён.');
  const expected = height * (1 + width * channels);
  if(budget){budget.decoded+=expected;check(budget.decoded<=LIMITS.expandedBytes,'Суммарный размер распакованных изображений больше 32 МиБ.');}
  let decoded;
  try { decoded = inflateSync(Buffer.concat(chunks), { maxOutputLength: expected }); }
  catch { throw new PolicyError('Повреждённые или слишком большие данные PNG.'); }
  check(decoded.length === expected, 'Некорректный размер данных PNG.');
  for (let y = 0; y < height; y++) check(decoded[y * (1 + width * channels)] <= 4, 'Некорректный фильтр PNG.');
  return { width, height, decodedBytes:expected };
}

function validateFile(name, bytes, budget) {
  safeName(name);
  check(bytes.length > 0 && bytes.length <= LIMITS.fileBytes, 'Каждый JSON/PNG должен быть не больше 2 МиБ.');
  return name.toLowerCase().endsWith('.json') ? validateJson(bytes,budget) : validatePng(bytes,LIMITS.fileBytes,budget);
}

// Deliberately small ZIP32 subset: stored/deflate, no encryption, links, nested archives or ZIP64.
export function unpackZip(input) {
  const b = Buffer.from(input);
  check(b.length >= 22 && b.length <= LIMITS.packageBytes, 'ZIP должен быть не больше 10 МиБ.');
  let end = -1;
  for (let p = b.length - 22; p >= Math.max(0, b.length - 65557); p--) {
    if (b.readUInt32LE(p) === 0x06054b50 && p + 22 + b.readUInt16LE(p + 20) === b.length) { end = p; break; }
  }
  check(end >= 0 && b.readUInt16LE(end + 4) === 0 && b.readUInt16LE(end + 6) === 0, 'Повреждённый, составной или ZIP64 архив.');
  const count = b.readUInt16LE(end + 10), centralSize = b.readUInt32LE(end + 12), central = b.readUInt32LE(end + 16);
  check(count > 0 && count <= LIMITS.entries && count === b.readUInt16LE(end + 8)
    && central + centralSize === end, 'Некорректный ZIP или больше 128 записей.');
  let pos = central, expanded = 0;
  const seen = new Map(), files = [], ranges = [], budget={decoded:0,jsonNodes:0};
  for (let n = 0; n < count; n++) {
    check(pos + 46 <= end && b.readUInt32LE(pos) === 0x02014b50, 'Повреждённый каталог ZIP.');
    const flags = b.readUInt16LE(pos + 8), method = b.readUInt16LE(pos + 10), crc = b.readUInt32LE(pos + 16);
    const compressed = b.readUInt32LE(pos + 20), size = b.readUInt32LE(pos + 24), len = b.readUInt16LE(pos + 28);
    const extra = b.readUInt16LE(pos + 30), comment = b.readUInt16LE(pos + 32), attrs = b.readUInt32LE(pos + 38), start = b.readUInt32LE(pos + 42);
    check(pos + 46 + len + extra + comment <= end && len > 0 && b.readUInt16LE(pos + 34) === 0
      && (flags & ~0x080e) === 0 && [0, 8].includes(method) && size !== 0xffffffff && compressed !== 0xffffffff,
    'Шифрование, ZIP64 и этот метод сжатия запрещены.');
    const rawName = b.subarray(pos + 46, pos + 46 + len);
    let name;
    try { name = new TextDecoder('utf-8', {fatal:true}).decode(rawName); } catch { throw new PolicyError('Некорректное имя в ZIP.'); }
    const directory = name.endsWith('/'); safeName(name, directory);
    const key = (directory ? name.slice(0, -1) : name).toLowerCase();
    check(!seen.has(key), 'Повторяющиеся имена в ZIP, в том числе с разным регистром.'); seen.set(key, directory);
    const unixType = (attrs >>> 16) & 0xf000;
    check([0, directory ? 0x4000 : 0x8000].includes(unixType) && !(attrs & 0x400), 'Ссылки и специальные файлы в ZIP запрещены.');
    check(size <= LIMITS.fileBytes && (directory ? size === 0 : size > 0)
      && size <= Math.max(1, compressed) * LIMITS.ratio, 'Слишком большой файл или чрезмерное сжатие ZIP.');
    expanded += size; check(expanded <= LIMITS.expandedBytes, 'После распаковки допускается не больше 32 МиБ.');
    check(start + 30 <= central && b.readUInt32LE(start) === 0x04034b50
      && b.readUInt16LE(start + 6) === flags && b.readUInt16LE(start + 8) === method, 'Повреждённый заголовок файла ZIP.');
    const localLen = b.readUInt16LE(start + 26), localExtra = b.readUInt16LE(start + 28), from = start + 30 + localLen + localExtra;
    check(localLen === len && b.subarray(start + 30, start + 30 + localLen).equals(rawName)
      && from + compressed <= central, 'Имя или размер файла ZIP не совпадает с каталогом.');
    let stop = from + compressed;
    if (flags & 8) {
      if (stop + 4 <= central && b.readUInt32LE(stop) === 0x08074b50) stop += 4;
      check(stop + 12 <= central && b.readUInt32LE(stop) === crc && b.readUInt32LE(stop + 4) === compressed
        && b.readUInt32LE(stop + 8) === size, 'Повреждённый дескриптор ZIP.'); stop += 12;
    } else check(b.readUInt32LE(start + 14) === crc && b.readUInt32LE(start + 18) === compressed
      && b.readUInt32LE(start + 22) === size, 'Размеры заголовков ZIP не совпадают.');
    ranges.push([start, stop]);
    let bytes;
    try { bytes = method === 0 ? b.subarray(from, from + compressed)
      : inflateRawSync(b.subarray(from, from + compressed), {maxOutputLength: Math.max(1, size)}); }
    catch { throw new PolicyError('ZIP повреждён или превышает лимит распаковки.'); }
    check(bytes.length === size && crc32(bytes) === crc, 'Контрольная сумма ZIP не совпадает.');
    if (!directory) { validateFile(name, bytes,budget); files.push({ name, bytes }); }
    pos += 46 + len + extra + comment;
  }
  check(pos === end && files.length > 0, 'Некорректный или пустой ZIP.');
  ranges.sort((a, z) => a[0] - z[0]);
  let cursor = 0;
  for (const [start, stop] of ranges) { check(start === cursor && stop > start, 'Перекрывающиеся или скрытые данные ZIP.'); cursor = stop; }
  check(cursor === central, 'Скрытые данные перед каталогом ZIP.');
  for (const [name] of seen) {
    const parts = name.split('/'); parts.pop();
    while (parts.length) { check(seen.get(parts.join('/')) !== false, 'Файл конфликтует с папкой в ZIP.'); parts.pop(); }
  }
  return files;
}

export function validatePackage(bytes, extension) {
  check(bytes.length > 0 && bytes.length <= LIMITS.packageBytes, 'Пакет должен быть не больше 10 МиБ.');
  const ext = String(extension).toLowerCase();
  check(['json', 'png', 'zip'].includes(ext), 'Поддерживаются только JSON, PNG и ZIP с проверкой.');
  const files = ext === 'zip' ? unpackZip(bytes) : (validateFile(`project.${ext}`, bytes), [{name:`project.${ext}`, bytes:Buffer.from(bytes)}]);
  return { files, sha256:sha256(bytes), bytes:bytes.length, extension:ext };
}

export function makeZip(files) {
  check(files.length > 0 && files.length <= LIMITS.entries, 'В папке должно быть от 1 до 128 файлов.');
  const local = [], central = []; let offset = 0;
  for (const file of files) {
    validateFile(file.name, file.bytes);
    const name = Buffer.from(file.name), crc = crc32(file.bytes), head = Buffer.alloc(30), entry = Buffer.alloc(46);
    head.writeUInt32LE(0x04034b50); head.writeUInt16LE(20, 4); head.writeUInt16LE(0x800, 6);
    head.writeUInt32LE(crc, 14); head.writeUInt32LE(file.bytes.length, 18); head.writeUInt32LE(file.bytes.length, 22); head.writeUInt16LE(name.length, 26);
    entry.writeUInt32LE(0x02014b50); entry.writeUInt16LE(20, 4); entry.writeUInt16LE(20, 6); entry.writeUInt16LE(0x800, 8);
    entry.writeUInt32LE(crc, 16); entry.writeUInt32LE(file.bytes.length, 20); entry.writeUInt32LE(file.bytes.length, 24);
    entry.writeUInt16LE(name.length, 28); entry.writeUInt32LE(offset, 42);
    local.push(head, name, file.bytes); central.push(entry, name); offset += head.length + name.length + file.bytes.length;
    check(offset <= LIMITS.packageBytes, 'Папка не помещается в ZIP размером 10 МиБ.');
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  const result = Buffer.concat([...local, directory, end]); validatePackage(result, 'zip'); return result;
}
