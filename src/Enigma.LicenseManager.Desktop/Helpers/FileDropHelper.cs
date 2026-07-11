using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;

namespace Enigma.LicenseManager.Desktop.Helpers;

public static class FileDropHelper
{
    public static readonly AttachedProperty<bool> IsEnabledProperty =
        AvaloniaProperty.RegisterAttached<Control, bool>("IsEnabled", typeof(FileDropHelper));

    static FileDropHelper()
    {
        IsEnabledProperty.Changed.AddClassHandler<Control>(OnIsEnabledChanged);
    }

    public static bool GetIsEnabled(Control control) => control.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(Control control, bool value) => control.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(Control control, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.NewValue is true)
        {
            DragDrop.SetAllowDrop(control, true);
            control.AddHandler(DragDrop.DragOverEvent, OnDragOver, RoutingStrategies.Bubble);
            control.AddHandler(DragDrop.DropEvent, OnDrop, RoutingStrategies.Bubble);
        }
        else
        {
            DragDrop.SetAllowDrop(control, false);
            control.RemoveHandler(DragDrop.DragOverEvent, OnDragOver);
            control.RemoveHandler(DragDrop.DropEvent, OnDrop);
        }
    }

    private static void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.DataTransfer.Contains(DataFormat.File)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private static void OnDrop(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer.TryGetFiles();

        if (files is { Length: > 0 }
            && GetPath(files[0]) is { } path
            && sender is TextBox textBox)
        {
            textBox.SetCurrentValue(TextBox.TextProperty, path);
            e.Handled = true;
        }
    }

    private static string? GetPath(IStorageItem item)
    {
        if (item.TryGetLocalPath() is { } path)
            return path;
        if (item.Path is { IsFile: true } uri)
            return Uri.UnescapeDataString(uri.LocalPath);
        return null;
    }
}
