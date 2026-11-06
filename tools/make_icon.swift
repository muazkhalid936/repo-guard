import AppKit

// Draws the app icon and writes an .iconset folder for iconutil. Usage: make_icon OUTPUT.iconset
let out = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

func draw(_ px: Int) -> Data? {
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                                     hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px)
    // macOS icon grid: the tile sits inside the canvas with a margin.
    let tile = NSRect(x: s * 0.098, y: s * 0.098, width: s * 0.804, height: s * 0.804)
    let path = NSBezierPath(roundedRect: tile, xRadius: s * 0.18, yRadius: s * 0.18)
    let top = NSColor(calibratedRed: 0.13, green: 0.68, blue: 0.45, alpha: 1)
    let bottom = NSColor(calibratedRed: 0.03, green: 0.34, blue: 0.33, alpha: 1)
    NSGradient(starting: top, ending: bottom)?.draw(in: path, angle: -90)
    let config = NSImage.SymbolConfiguration(pointSize: s * 0.46, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [NSColor(calibratedRed: 0.03, green: 0.42, blue: 0.36, alpha: 1), .white]))
    if let symbol = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(config) {
        let size = symbol.size
        symbol.draw(in: NSRect(x: (s - size.width) / 2, y: (s - size.height) / 2, width: size.width, height: size.height))
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])
}

for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        if let data = draw(base * scale) { try? data.write(to: URL(fileURLWithPath: "\(out)/\(name)")) }
    }
}
