// Native app icons rendered from the code-native Jade triangle. No network,
// image service or npm dependency is needed by either platform build.
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { deflateSync } from 'node:zlib'
import { spawnSync } from 'node:child_process'

const MASTER_SIZE = 2048
const edges = [
  [512, 222, 242, 726, 18], [242, 726, 782, 726, 18], [782, 726, 512, 222, 18],
  [512, 420, 386, 654, 14], [386, 654, 638, 654, 14], [638, 654, 512, 420, 14],
  [512, 546, 512, 816, 11], [332, 834, 692, 834, 11],
]

function segmentDistanceSquared(x, y, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
  return (x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2
}

function masterPixels() {
  const pixels = Buffer.alloc(MASTER_SIZE * MASTER_SIZE * 4)
  const stops = [[47, 128, 103], [23, 97, 74]]
  for (let py = 0; py < MASTER_SIZE; py++) for (let px = 0; px < MASTER_SIZE; px++) {
    const x = (px + 0.5) / 2, y = (py + 0.5) / 2
    const cx = Math.max(260, Math.min(764, x)), cy = Math.max(260, Math.min(764, y))
    if ((x - cx) ** 2 + (y - cy) ** 2 > 196 ** 2) continue
    const at = (py * MASTER_SIZE + px) * 4
    const white = edges.some(([ax, ay, bx, by, radius]) => segmentDistanceSquared(x, y, ax, ay, bx, by) <= radius ** 2)
    const t = (y - 64) / 896
    for (let channel = 0; channel < 3; channel++) pixels[at + channel] = white ? 255 : Math.round(stops[0][channel] * (1 - t) + stops[1][channel] * t)
    pixels[at + 3] = 255
  }
  return pixels
}

function crc32(bytes) {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(name, data) {
  const tag = Buffer.from(name), size = Buffer.alloc(4), checksum = Buffer.alloc(4)
  size.writeUInt32BE(data.length)
  checksum.writeUInt32BE(crc32(Buffer.concat([tag, data])))
  return Buffer.concat([size, tag, data, checksum])
}

function png(master, size) {
  const rows = Buffer.alloc(size * (1 + size * 4))
  // Area averaging keeps white strokes legible and avoids dark alpha edges.
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const sx = Math.floor(x * MASTER_SIZE / size), ex = Math.floor((x + 1) * MASTER_SIZE / size)
    const sy = Math.floor(y * MASTER_SIZE / size), ey = Math.floor((y + 1) * MASTER_SIZE / size)
    let red = 0, green = 0, blue = 0, alpha = 0
    for (let yy = sy; yy < ey; yy++) for (let xx = sx; xx < ex; xx++) {
      const at = (yy * MASTER_SIZE + xx) * 4
      red += master[at]; green += master[at + 1]; blue += master[at + 2]; alpha += master[at + 3]
    }
    const at = y * (1 + size * 4) + 1 + x * 4
    if (alpha) {
      rows[at] = Math.round(red * 255 / alpha)
      rows[at + 1] = Math.round(green * 255 / alpha)
      rows[at + 2] = Math.round(blue * 255 / alpha)
      rows[at + 3] = Math.round(alpha / ((ex - sx) * (ey - sy)))
    }
  }
  const header = Buffer.alloc(13)
  header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))])
}

function ico(images) {
  const sizes = [16, 24, 32, 48, 64, 128, 256]
  const header = Buffer.alloc(6 + sizes.length * 16)
  header.writeUInt16LE(1, 2); header.writeUInt16LE(sizes.length, 4)
  let offset = header.length
  for (let i = 0; i < sizes.length; i++) {
    const size = sizes[i], data = images.get(size), at = 6 + i * 16
    header[at] = size === 256 ? 0 : size; header[at + 1] = header[at]
    header.writeUInt16LE(1, at + 4); header.writeUInt16LE(32, at + 6)
    header.writeUInt32LE(data.length, at + 8); header.writeUInt32LE(offset, at + 12)
    offset += data.length
  }
  return Buffer.concat([header, ...sizes.map(size => images.get(size))])
}

export async function generateIcons(resources, os) {
  if (!['darwin', 'windows'].includes(os)) throw new Error('Icon target must be darwin or windows')
  await mkdir(resources, { recursive: true })
  const master = masterPixels(), images = new Map()
  for (const size of [16, 24, 32, 48, 64, 128, 256, 512, 1024]) images.set(size, png(master, size))
  await writeFile(join(resources, 'icon.png'), images.get(1024))
  await writeFile(join(resources, 'icon.ico'), ico(images))
  if (os === 'darwin') {
    if (process.platform !== 'darwin') throw new Error('macOS ICNS generation requires native iconutil')
    const iconset = join(resources, 'LuminaVPN.iconset')
    await mkdir(iconset, { recursive: true })
    try {
      for (const size of [16, 32, 128, 256, 512]) {
        await writeFile(join(iconset, `icon_${size}x${size}.png`), images.get(size))
        await writeFile(join(iconset, `icon_${size}x${size}@2x.png`), images.get(size * 2))
      }
      const result = spawnSync('/usr/bin/iconutil', ['-c', 'icns', iconset, '-o', join(resources, 'icon.icns')], { shell: false, stdio: 'pipe' })
      if (result.error || result.status !== 0) throw new Error('Native ICNS compilation failed')
    } finally { await rm(iconset, { recursive: true, force: true }) }
  }
}
