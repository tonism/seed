#!/usr/bin/env swift
import AppKit
import Foundation
import Vision

if CommandLine.arguments.count != 2 {
    fputs("usage: ocr-vision.swift image.png\n", stderr)
    exit(2)
}

let url = URL(fileURLWithPath: CommandLine.arguments[1])
guard let image = NSImage(contentsOf: url) else {
    fputs("ocr: could not load image\n", stderr)
    exit(1)
}

var rect = NSRect(origin: .zero, size: image.size)
guard let cgImage = image.cgImage(forProposedRect: &rect, context: nil, hints: nil) else {
    fputs("ocr: could not create CGImage\n", stderr)
    exit(1)
}

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
request.minimumTextHeight = 0.008
if #available(macOS 13.0, *) {
    request.automaticallyDetectsLanguage = false
}

let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
do {
    try handler.perform([request])
} catch {
    fputs("ocr: \(error)\n", stderr)
    exit(1)
}

let observations = request.results ?? []
let lines = observations.compactMap { observation -> String? in
    guard let candidate = observation.topCandidates(1).first else {
        return nil
    }
    let text = candidate.string.trimmingCharacters(in: .whitespacesAndNewlines)
    return text.isEmpty ? nil : text
}

for line in lines {
    print(line)
}
