using Avalonia;
using Avalonia.Controls;

namespace Enigma.LicenseManager.Desktop.Controls;

public class ProgressOverlayCard : ContentControl
{
    public static readonly StyledProperty<string?> TitleProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, string?>(nameof(Title));

    public static readonly StyledProperty<bool> IsIndeterminateProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, bool>(nameof(IsIndeterminate), true);

    public static readonly StyledProperty<double> ProgressProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, double>(nameof(Progress));

    public static readonly StyledProperty<double> MinimumProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, double>(nameof(Minimum));

    public static readonly StyledProperty<double> MaximumProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, double>(nameof(Maximum), 100);

    public static readonly StyledProperty<string?> MessageProperty =
        AvaloniaProperty.Register<ProgressOverlayCard, string?>(nameof(Message));

    public string? Title
    {
        get => GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public bool IsIndeterminate
    {
        get => GetValue(IsIndeterminateProperty);
        set => SetValue(IsIndeterminateProperty, value);
    }

    public double Progress
    {
        get => GetValue(ProgressProperty);
        set => SetValue(ProgressProperty, value);
    }

    public double Minimum
    {
        get => GetValue(MinimumProperty);
        set => SetValue(MinimumProperty, value);
    }

    public double Maximum
    {
        get => GetValue(MaximumProperty);
        set => SetValue(MaximumProperty, value);
    }

    public string? Message
    {
        get => GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }
}
