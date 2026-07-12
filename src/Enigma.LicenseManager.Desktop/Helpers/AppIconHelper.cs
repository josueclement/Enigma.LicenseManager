using System;
using System.Collections.Generic;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using PhosphorIconsAvalonia;

namespace Enigma.LicenseManager.Desktop.Helpers;

public static class AppIconHelper
{
    private static readonly int[] IconSizes = [16, 24, 32, 48, 64, 128, 256];

    public static WindowIcon CreateWindowIcon(
        Icon icon,
        IconType iconType = IconType.fill,
        Color? color = null)
    {
        var brush = new SolidColorBrush(color ?? Colors.White);
        var drawingImage = IconService.CreateDrawingImage(icon, iconType, brush);

        var pngImages = new List<byte[]>(IconSizes.Length);
        foreach (var size in IconSizes)
        {
            pngImages.Add(RenderToPng(drawingImage, size));
        }

        var icoStream = new MemoryStream();
        WriteIco(icoStream, pngImages, IconSizes);
        icoStream.Position = 0;

        return new WindowIcon(icoStream);
    }

    private static byte[] RenderToPng(DrawingImage drawingImage, int size)
    {
        var image = new Image
        {
            Source = drawingImage,
            Width = size,
            Height = size
        };

        image.Measure(new Size(size, size));
        image.Arrange(new Rect(0, 0, size, size));

        var rtb = new RenderTargetBitmap(new PixelSize(size, size));
        rtb.Render(image);

        using var ms = new MemoryStream();
        rtb.Save(ms, PngBitmapEncoderOptions.Default);
        return ms.ToArray();
    }

    private static void WriteIco(Stream output, IReadOnlyList<byte[]> pngImages, int[] sizes)
    {
        using var writer = new BinaryWriter(output, System.Text.Encoding.UTF8, leaveOpen: true);

        // ICO header (6 bytes)
        writer.Write((ushort)0);                    // Reserved
        writer.Write((ushort)1);                    // Type: 1 = ICO
        writer.Write((ushort)pngImages.Count);      // Number of images

        var dataOffset = 6 + 16 * pngImages.Count;

        // Directory entries (16 bytes each)
        for (var i = 0; i < pngImages.Count; i++)
        {
            var s = sizes[i];
            var pngData = pngImages[i];

            writer.Write((byte)(s >= 256 ? 0 : s));    // Width (0 = 256)
            writer.Write((byte)(s >= 256 ? 0 : s));    // Height (0 = 256)
            writer.Write((byte)0);                      // Color palette count
            writer.Write((byte)0);                      // Reserved
            writer.Write((ushort)1);                    // Color planes
            writer.Write((ushort)32);                   // Bits per pixel
            writer.Write((uint)pngData.Length);         // Image data size
            writer.Write((uint)dataOffset);             // Offset to image data

            dataOffset += pngData.Length;
        }

        foreach (var pngData in pngImages)
        {
            writer.Write(pngData);
        }
    }
}
