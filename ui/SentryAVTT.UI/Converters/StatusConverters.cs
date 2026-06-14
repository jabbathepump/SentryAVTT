using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using SentryAVTT.UI.Models;

namespace SentryAVTT.UI.Converters;

[ValueConversion(typeof(ScanStatus), typeof(Brush))]
public sealed class StatusToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ScanStatus status)
        {
            return status switch
            {
                ScanStatus.Clean => new SolidColorBrush(Color.FromRgb(16, 185, 129)),
                ScanStatus.ThreatDetected => new SolidColorBrush(Color.FromRgb(239, 68, 68)),
                ScanStatus.Scanning => new SolidColorBrush(Color.FromRgb(250, 204, 21)),
                ScanStatus.Error => new SolidColorBrush(Color.FromRgb(249, 115, 22)),
                _ => new SolidColorBrush(Color.FromRgb(156, 163, 175)),
            };
        }
        return new SolidColorBrush(Color.FromRgb(156, 163, 175));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(ScanStatus), typeof(string))]
public sealed class StatusToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ScanStatus status)
        {
            return status switch
            {
                ScanStatus.Clean => "SentryAVTT is protecting your PC",
                ScanStatus.ThreatDetected => "Threats detected — action required",
                ScanStatus.Scanning => "Scanning in progress...",
                ScanStatus.Error => "Scan encountered an error",
                _ => "SentryAVTT is ready",
            };
        }
        return "SentryAVTT is ready";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(ScanStatus), typeof(string))]
public sealed class StatusToGlyphConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ScanStatus status)
        {
            return status switch
            {
                ScanStatus.Clean => "\uE734",
                ScanStatus.ThreatDetected => "\uE783",
                ScanStatus.Scanning => "\uE768",
                ScanStatus.Error => "\uE814",
                _ => "\uE734",
            };
        }
        return "\uE734";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(bool), typeof(string))]
public sealed class BoolToAdminLabelConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? "Hide Admin Console" : "Show Admin Console";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

[ValueConversion(typeof(bool), typeof(bool))]
public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : value;
}
