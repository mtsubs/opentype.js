import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import sfnt from '../../src/tables/sfnt.mjs';
import table from '../../src/table.mjs';
import cmap from '../../src/tables/cmap.mjs';
import head from '../../src/tables/head.mjs';
import hhea from '../../src/tables/hhea.mjs';
import maxp from '../../src/tables/maxp.mjs';
import name from '../../src/tables/name.mjs';
import post from '../../src/tables/post.mjs';

const TRUE_TYPE_SIGNATURE = String.fromCharCode(0, 1, 0, 0);
const COMPOSITE_FLAGS = {
    ARG_1_AND_2_ARE_WORDS: 0x0001,
    ARGS_ARE_XY_VALUES: 0x0002,
    MORE_COMPONENTS: 0x0020
};

function makeByteTable(tableName, bytes) {
    return new table.Table(tableName, bytes.map((value, index) => ({
        name: `byte_${index}`,
        type: 'BYTE',
        value
    })));
}

function makeUShortTable(tableName, values) {
    return new table.Table(tableName, values.map((value, index) => ({
        name: `ushort_${index}`,
        type: 'USHORT',
        value
    })));
}

function makeHmtxTable(advanceWidths, leftSideBearings) {
    const fields = [];
    for (let i = 0; i < advanceWidths.length; i += 1) {
        fields.push({name: `advanceWidth_${i}`, type: 'USHORT', value: advanceWidths[i]});
        fields.push({name: `leftSideBearing_${i}`, type: 'SHORT', value: leftSideBearings[i]});
    }
    return new table.Table('hmtx', fields);
}

function createNames() {
    const unicode = {
        copyright: {en: ' '},
        fontFamily: {en: 'Composite Cycle Test'},
        fontSubfamily: {en: 'Regular'},
        uniqueID: {en: 'Composite Cycle Test Regular'},
        fullName: {en: 'Composite Cycle Test Regular'},
        version: {en: 'Version 1.0'},
        postScriptName: {en: 'CompositeCycleTest-Regular'},
        trademark: {en: ' '}
    };

    return {
        unicode,
        windows: unicode,
        macintosh: unicode
    };
}

function createGlyphMetadata() {
    const glyphs = [
        {name: '.notdef', unicodes: []},
        {name: 'cycleA', unicode: 65, unicodes: [65]},
        {name: 'cycleB', unicode: 66, unicodes: [66]}
    ];

    return {
        length: glyphs.length,
        get(index) {
            return glyphs[index];
        }
    };
}

function createGlyfBytes() {
    return [
        // glyph 0: empty .notdef
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,

        // glyph 1: composite referencing glyph 2
        0xFF, 0xFF,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x23,
        0x00, 0x02,
        0x00, 0x00,
        0x00, 0x00,

        // glyph 2: composite referencing glyph 1
        0xFF, 0xFF,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x03,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00
    ];
}

export function makeCompositeCycleFontBuffer() {
    const glyphs = createGlyphMetadata();
    const tables = [
        cmap.make(glyphs),
        head.make({
            unitsPerEm: 1000,
            indexToLocFormat: 0,
            lowestRecPPEM: 3
        }),
        hhea.make({
            ascender: 800,
            descender: -200,
            advanceWidthMax: 500,
            numberOfHMetrics: glyphs.length
        }),
        maxp.make(glyphs.length),
        makeByteTable('glyf', createGlyfBytes()),
        makeUShortTable('loca', [0, 5, 14, 23]),
        makeHmtxTable([500, 500, 500], [0, 0, 0]),
        name.make(createNames(), []),
        post.make({tables: {}})
    ];

    const sfntTable = sfnt.make(tables);
    sfntTable.version = TRUE_TYPE_SIGNATURE;

    const bytes = sfntTable.encode();
    const checkSum = sfnt.computeCheckSum(bytes);
    for (let i = 0; i < sfntTable.fields.length; i += 1) {
        if (sfntTable.fields[i].name === 'head table') {
            sfntTable.fields[i].value.checkSumAdjustment = 0xB1B0AFBA - checkSum;
            break;
        }
    }

    return new Uint8Array(sfntTable.encode()).buffer;
}

const outputPath = fileURLToPath(new URL('./CompositeCycle.ttf', import.meta.url));
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const buffer = new Uint8Array(makeCompositeCycleFontBuffer());
    writeFileSync(outputPath, buffer);
    const aComponentFlags = COMPOSITE_FLAGS.ARG_1_AND_2_ARE_WORDS |
        COMPOSITE_FLAGS.ARGS_ARE_XY_VALUES |
        COMPOSITE_FLAGS.MORE_COMPONENTS;
    const bComponentFlags = COMPOSITE_FLAGS.ARG_1_AND_2_ARE_WORDS |
        COMPOSITE_FLAGS.ARGS_ARE_XY_VALUES;
    console.log(`Wrote ${outputPath} (${buffer.byteLength} bytes, flags ${aComponentFlags}/${bComponentFlags}).`);
}
