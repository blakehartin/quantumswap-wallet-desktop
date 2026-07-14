/**
 * Build icon assets from src/assets/svg/quantumswap.svg
 * - PNGs: 128.png, 48.png, app/dp.png, app/icon.png (transparent)
 * - JPG: 128.jpg (opaque)
 * - ICO: app/icon.ico (multi-size, for Windows exe)
 * - ICNS: app/icon.icns (macOS)
 * - loading.gif: pulse animation
 */

const fs = require("fs");
const path = require("path");
const sharp = require("sharp");
const png2icons = require("png2icons");
const { GIFEncoder, quantize, applyPalette } = require("gifenc");

const ROOT = path.join(__dirname, "..");
const SVG_PATH = path.join(ROOT, "src", "assets", "svg", "quantumswap.svg");
const ICONS_DIR = path.join(ROOT, "src", "assets", "icons");
const APP_ICONS_DIR = path.join(ICONS_DIR, "app");

const sizes = {
  "128.png": 128,
  "48.png": 48,
  "app/dp.png": 64,
  "app/icon.png": 512,
};

// SVG with background rect removed so output has transparent background
function svgWithTransparentBackground(svgBuffer) {
  const svg = svgBuffer.toString("utf8");
  const noBg = svg.replace(
    /<rect width="100%" height="100%" fill="#0b0614"\/>/,
    "<!-- background removed for transparency -->"
  );
  return Buffer.from(noBg, "utf8");
}

// Re-encode image to strip all metadata (EXIF, XMP, IPTC, PNG tEXt chunks, etc.)
async function stripMetadata(buffer, format, outPath) {
  const pipeline = sharp(buffer);
  if (format === "png") {
    await pipeline.png().toFile(outPath);
  } else if (format === "jpeg") {
    await pipeline.jpeg({ quality: 90 }).toFile(outPath);
  }
}

async function stripMetadataToBuffer(buffer) {
  return sharp(buffer).png().toBuffer();
}

// Remove GIF comment blocks (0x21 0xFE ...) so the file has no comment metadata
function stripGifCommentBlocks(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const out = [];
  let i = 0;
  while (i < buf.length) {
    if (buf[i] === 0x21 && buf[i + 1] === 0xfe) {
      i += 2;
      while (i < buf.length) {
        const blockSize = buf[i];
        i += 1;
        if (blockSize === 0) break;
        i += blockSize;
      }
      continue;
    }
    out.push(buf[i]);
    i += 1;
  }
  return Buffer.from(out);
}

async function main() {
  const svgBuffer = fs.readFileSync(SVG_PATH);
  const svgTransparent = svgWithTransparentBackground(svgBuffer);

  console.log("Building icons from quantumswap.svg...\n");

  // ---- 1) Transparent PNGs (no background in SVG, no metadata) ----
  console.log("1) Creating transparent PNGs...");
  for (const [file, size] of Object.entries(sizes)) {
    const outPath = path.join(ICONS_DIR, file);
    const pngBuffer = await sharp(svgTransparent)
      .resize(size, size)
      .png()
      .toBuffer();
    await stripMetadata(pngBuffer, "png", outPath);
    console.log("   ", file, size + "x" + size);
  }

  // ---- 2) JPG (opaque, keep background, no metadata) and ICO ----
  console.log("\n2) Creating 128.jpg and app/icon.ico...");
  const jpgBuffer = await sharp(svgBuffer)
    .resize(128, 128)
    .jpeg({ quality: 90 })
    .toBuffer();
  await stripMetadata(jpgBuffer, "jpeg", path.join(ICONS_DIR, "128.jpg"));
  console.log("   128.jpg 128x128");

  // ICO/ICNS need a high-res PNG with transparent background and no metadata
  let iconPng1024 = await sharp(svgTransparent)
    .resize(1024, 1024)
    .png()
    .toBuffer();
  iconPng1024 = await stripMetadataToBuffer(iconPng1024);

  const icoBuffer = png2icons.createICO(
    iconPng1024,
    png2icons.BICUBIC,
    0,
    false,
    true
  );
  if (icoBuffer) {
    fs.writeFileSync(path.join(APP_ICONS_DIR, "icon.ico"), icoBuffer);
    console.log("   app/icon.ico (multi-size, for Windows exe)");
  } else {
    console.error("   Failed to create icon.ico");
  }

  // ---- 3) ICNS ----
  console.log("\n3) Creating app/icon.icns...");
  png2icons.clearCache();
  const icnsBuffer = png2icons.createICNS(iconPng1024, png2icons.BICUBIC, 0);
  if (icnsBuffer) {
    fs.writeFileSync(path.join(APP_ICONS_DIR, "icon.icns"), icnsBuffer);
    console.log("   app/icon.icns");
  } else {
    console.error("   Failed to create icon.icns");
  }

  // ---- 4) loading.gif with pulse effect (circular black background, rest transparent) ----
  // Frame 144x144 so circle can touch edges (r = gifSize/2) and logo at max pulse still fits inside
  console.log("\n4) Creating loading.gif (pulse effect, circular black bg)...");
  const logoSize = 128;
  const gifSize = 144;
  const circleRadius = Math.floor(gifSize / 2);
  const logoInset = Math.floor((gifSize - logoSize) / 2);
  const pulseScales = [0.88, 0.92, 0.96, 1.0, 1.04, 1.0, 0.96, 0.92];

  const blackCircleSvg = Buffer.from(
    `<svg width="${gifSize}" height="${gifSize}" viewBox="0 0 ${gifSize} ${gifSize}" xmlns="http://www.w3.org/2000/svg"><circle cx="${gifSize / 2}" cy="${gifSize / 2}" r="${circleRadius}" fill="black"/></svg>`,
    "utf8"
  );
  const blackCirclePng = await sharp(blackCircleSvg).resize(gifSize, gifSize).png().toBuffer();

  const gif = GIFEncoder();
  const frameBuffers = [];

  for (const scale of pulseScales) {
    const w = Math.round(logoSize * scale);
    const h = Math.round(logoSize * scale);

    let logoLayer;
    if (w <= logoSize && h <= logoSize) {
      const left = Math.floor((logoSize - w) / 2);
      const top = Math.floor((logoSize - h) / 2);
      const scaled = await sharp(svgTransparent).resize(w, h).png().toBuffer();
      logoLayer = await sharp({
        create: {
          width: logoSize,
          height: logoSize,
          channels: 4,
          background: { r: 0, g: 0, b: 0, alpha: 0 },
        },
      })
        .composite([{ input: scaled, left, top }])
        .png()
        .toBuffer();
    } else {
      const scaled = await sharp(svgTransparent).resize(w, h).png().toBuffer();
      const cropLeft = Math.floor((w - logoSize) / 2);
      const cropTop = Math.floor((h - logoSize) / 2);
      logoLayer = await sharp(scaled)
        .extract({ left: cropLeft, top: cropTop, width: logoSize, height: logoSize })
        .png()
        .toBuffer();
    }

    const frameBuffer = await sharp({
      create: {
        width: gifSize,
        height: gifSize,
        channels: 4,
        background: { r: 0, g: 0, b: 0, alpha: 0 },
      },
    })
      .composite([
        { input: blackCirclePng, left: 0, top: 0 },
        { input: logoLayer, left: logoInset, top: logoInset },
      ])
      .raw()
      .toBuffer();

    frameBuffers.push(new Uint8Array(frameBuffer));
  }

  // Quantize first frame for global palette (with alpha for transparency)
  const palette = quantize(frameBuffers[0], 256, {
    format: "rgba4444",
    oneBitAlpha: true,
  });

  for (let i = 0; i < frameBuffers.length; i++) {
    const index = applyPalette(frameBuffers[i], palette, "rgba4444");
    gif.writeFrame(index, gifSize, gifSize, {
      palette,
      delay: 120,
      transparent: true,
      transparentIndex: 0,
    });
  }

  gif.finish();
  let gifBuffer = Buffer.from(gif.bytes());
  gifBuffer = stripGifCommentBlocks(gifBuffer);
  fs.writeFileSync(path.join(ICONS_DIR, "loading.gif"), gifBuffer);

  console.log("   loading.gif", gifSize + "x" + gifSize, pulseScales.length, "frames");

  console.log("\nDone.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
