#!/usr/bin/env node
'use strict';
// pe-inspect: read-only inspector for Windows PE files (.exe, .dll).
// Shows headers and sections, imports, and exports. Never executes the file.
// No dependencies beyond Node.js core.

const fs = require('fs');

const MACHINES = {
  0x014c: 'x86 (i386)',
  0x8664: 'x64 (AMD64)',
  0xaa64: 'ARM64',
  0x01c4: 'ARM Thumb-2',
};
const SUBSYSTEMS = {
  1: 'Native',
  2: 'Windows GUI',
  3: 'Windows console',
  9: 'Windows CE GUI',
  10: 'EFI application',
  14: 'Xbox',
  16: 'Windows boot application',
};

function usage() {
  console.error('usage: pe-inspect <file.exe|file.dll> [--info] [--imports] [--exports] [--all]');
  console.error('  default with no option is --info');
  process.exit(2);
}

function cstring(buf, off) {
  if (off === null || off < 0 || off >= buf.length) return '';
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.toString('latin1', off, end);
}

function parsePE(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) {
    throw new Error('not a PE file (missing MZ header)');
  }
  const peOff = buf.readUInt32LE(0x3c);
  if (peOff + 24 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) {
    throw new Error('not a PE file (missing PE signature)');
  }

  const coff = peOff + 4;
  const machine = buf.readUInt16LE(coff);
  const numSections = buf.readUInt16LE(coff + 2);
  const timestamp = buf.readUInt32LE(coff + 4);
  const optSize = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);

  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new Error(`unknown optional header magic 0x${magic.toString(16)}`);
  }
  const is64 = magic === 0x20b;

  const entryRva = buf.readUInt32LE(opt + 16);
  const imageBase = is64 ? buf.readBigUInt64LE(opt + 24) : BigInt(buf.readUInt32LE(opt + 28));
  const subsystem = buf.readUInt16LE(opt + 68);
  const sizeOfImage = buf.readUInt32LE(opt + 56);

  const ddStart = opt + (is64 ? 112 : 96);
  const numDD = buf.readUInt32LE(ddStart - 4);
  const dirs = [];
  for (let i = 0; i < Math.min(numDD, 16); i++) {
    dirs.push({ rva: buf.readUInt32LE(ddStart + i * 8), size: buf.readUInt32LE(ddStart + i * 8 + 4) });
  }

  const sectStart = opt + optSize;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = sectStart + i * 40;
    sections.push({
      name: buf.toString('latin1', s, s + 8).replace(/\0.*$/s, ''),
      vsize: buf.readUInt32LE(s + 8),
      rva: buf.readUInt32LE(s + 12),
      rawSize: buf.readUInt32LE(s + 16),
      rawPtr: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }

  return { machine, timestamp, characteristics, is64, entryRva, imageBase, subsystem, sizeOfImage, dirs, sections, buf };
}

// Convert a relative virtual address to a file offset using the section table.
function rvaToOffset(pe, rva) {
  if (rva === 0) return null;
  if (pe.sections.length && rva < pe.sections[0].rva) return rva; // header area
  for (const s of pe.sections) {
    const span = Math.max(s.vsize, s.rawSize);
    if (rva >= s.rva && rva < s.rva + span) {
      const off = rva - s.rva + s.rawPtr;
      return off < pe.buf.length ? off : null;
    }
  }
  return null;
}

function showInfo(pe, name) {
  const ts = new Date(pe.timestamp * 1000).toISOString();
  const isDll = (pe.characteristics & 0x2000) !== 0;
  console.log(`File:           ${name}`);
  console.log(`Format:         PE${pe.is64 ? '32+' : '32'} (${isDll ? 'DLL' : 'executable'})`);
  console.log(`Machine:        ${MACHINES[pe.machine] || `unknown (0x${pe.machine.toString(16)})`}`);
  console.log(`Subsystem:      ${SUBSYSTEMS[pe.subsystem] || pe.subsystem}`);
  console.log(`Image base:     0x${pe.imageBase.toString(16)}`);
  console.log(`Entry RVA:      0x${pe.entryRva.toString(16)}`);
  console.log(`Image size:     ${pe.sizeOfImage} bytes`);
  console.log(`Built (UTC):    ${ts}`);
  console.log('');
  console.log('Sections:');
  console.log('  Name      VirtSize    RawSize   RVA        Flags');
  for (const s of pe.sections) {
    const flags = [
      s.chars & 0x20000000 ? 'X' : '-',
      s.chars & 0x40000000 ? 'R' : '-',
      s.chars & 0x80000000 ? 'W' : '-',
    ].join('');
    console.log(
      `  ${s.name.padEnd(8)}  ${String(s.vsize).padStart(9)}  ${String(s.rawSize).padStart(9)}   0x${s.rva.toString(16).padStart(8, '0')}  ${flags}`
    );
  }
}

function showImports(pe) {
  const dir = pe.dirs[1];
  if (!dir || !dir.rva) {
    console.log('Imports: none');
    return;
  }
  const buf = pe.buf;
  const thunkSize = pe.is64 ? 8 : 4;
  let off = rvaToOffset(pe, dir.rva);
  if (off === null) throw new Error('import directory is outside the file');

  let count = 0;
  while (off + 20 <= buf.length) {
    const origThunk = buf.readUInt32LE(off);
    const nameRva = buf.readUInt32LE(off + 12);
    const firstThunk = buf.readUInt32LE(off + 16);
    if (origThunk === 0 && nameRva === 0 && firstThunk === 0) break;

    const dllName = cstring(buf, rvaToOffset(pe, nameRva));
    console.log(`${dllName}`);

    // Prefer the lookup table (OriginalFirstThunk); fall back to the IAT.
    let tOff = rvaToOffset(pe, origThunk || firstThunk);
    while (tOff !== null && tOff + thunkSize <= buf.length) {
      const lo = buf.readUInt32LE(tOff);
      const hi = pe.is64 ? buf.readUInt32LE(tOff + 4) : 0;
      if (lo === 0 && hi === 0) break;
      const isOrdinal = pe.is64 ? (hi & 0x80000000) !== 0 : (lo & 0x80000000) !== 0;
      if (isOrdinal) {
        console.log(`    ordinal #${lo & 0xffff}`);
      } else {
        const hintNameOff = rvaToOffset(pe, lo);
        const fn = hintNameOff === null ? '(unresolved)' : cstring(buf, hintNameOff + 2);
        console.log(`    ${fn}`);
      }
      count++;
      tOff += thunkSize;
    }
    off += 20;
  }
  console.log(`\n${count} imported function(s)`);
}

function showExports(pe) {
  const dir = pe.dirs[0];
  if (!dir || !dir.rva) {
    console.log('Exports: none');
    return;
  }
  const buf = pe.buf;
  const off = rvaToOffset(pe, dir.rva);
  if (off === null || off + 40 > buf.length) throw new Error('export directory is outside the file');

  const dllName = cstring(buf, rvaToOffset(pe, buf.readUInt32LE(off + 12)));
  const base = buf.readUInt32LE(off + 16);
  const numFuncs = buf.readUInt32LE(off + 20);
  const numNames = buf.readUInt32LE(off + 24);
  const funcsOff = rvaToOffset(pe, buf.readUInt32LE(off + 28));
  const namesOff = rvaToOffset(pe, buf.readUInt32LE(off + 32));
  const ordsOff = rvaToOffset(pe, buf.readUInt32LE(off + 36));
  const expStart = dir.rva;
  const expEnd = dir.rva + dir.size;

  // Map function index -> name, where a name exists.
  const names = new Map();
  for (let i = 0; i < numNames; i++) {
    const nameOff = rvaToOffset(pe, buf.readUInt32LE(namesOff + i * 4));
    const idx = buf.readUInt16LE(ordsOff + i * 2);
    names.set(idx, cstring(buf, nameOff));
  }

  console.log(`Export DLL name: ${dllName}`);
  console.log(`Functions: ${numFuncs}   Named: ${numNames}\n`);
  console.log('  Ordinal  Name                                 RVA         Target');
  for (let i = 0; i < numFuncs; i++) {
    const rva = buf.readUInt32LE(funcsOff + i * 4);
    if (rva === 0) continue; // unused slot
    const ordinal = base + i;
    const name = names.get(i) || `(ordinal ${ordinal})`;
    let target = '';
    if (rva >= expStart && rva < expEnd) {
      // Forwarded export: the RVA points to a "dll.function" string.
      target = `-> ${cstring(buf, rvaToOffset(pe, rva))}`;
    }
    console.log(
      `  ${String(ordinal).padStart(7)}  ${name.padEnd(36)} 0x${rva.toString(16).padStart(8, '0')}  ${target}`
    );
  }
}

function main(argv) {
  const args = argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  const flags = new Set(args.filter((a) => a.startsWith('--')));
  const known = new Set(['--info', '--imports', '--exports', '--all']);
  if (!file || [...flags].some((f) => !known.has(f))) usage();

  let buf;
  try {
    buf = fs.readFileSync(file);
  } catch (e) {
    console.error(`pe-inspect: cannot read ${file}: ${e.message}`);
    process.exit(1);
  }

  let pe;
  try {
    pe = parsePE(buf);
  } catch (e) {
    console.error(`pe-inspect: ${file}: ${e.message}`);
    process.exit(1);
  }

  const all = flags.has('--all');
  const wantInfo = all || flags.has('--info') || flags.size === 0;
  const wantImports = all || flags.has('--imports');
  const wantExports = all || flags.has('--exports');

  try {
    if (wantInfo) showInfo(pe, file);
    if (wantImports) {
      if (wantInfo) console.log('');
      showImports(pe);
    }
    if (wantExports) {
      if (wantInfo || wantImports) console.log('');
      showExports(pe);
    }
  } catch (e) {
    // Malformed tables: report and stop without a crash trace.
    console.error(`pe-inspect: ${file}: malformed table: ${e.message}`);
    process.exit(1);
  }
}

main(process.argv);
