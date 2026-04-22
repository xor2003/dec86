#region License
/* 
 * Copyright (C) 1999-2026 John Källén.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#endregion

using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Reko.Core;
using Reko.Core.Collections;
using Reko.Core.Loading;
using Reko.Core.Types;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Reko.UserInterfaces.AvaloniaUI.Controls;

/// <summary>
/// Renders <see cref="ImageSegment"/>s and <see cref="ImageMapItem"/>s with zoom and offset support.
/// </summary>
public class ImageMapControl : Control
{
    private const double SeparatorWidth = 1.0;

    public event EventHandler<ImageMapClickEventArgs>? ItemClicked;


    public static readonly StyledProperty<SegmentMap?> SegmentMapProperty =
        AvaloniaProperty.Register<ImageMapControl, SegmentMap?>(nameof(SegmentMap), defaultValue: null);

    public static readonly StyledProperty<ImageMap?> ImageMapProperty =
        AvaloniaProperty.Register<ImageMapControl, ImageMap?>(nameof(ImageMap), defaultValue: null);

    public static readonly StyledProperty<double> ZoomProperty =
        AvaloniaProperty.Register<ImageMapControl, double>(nameof(Zoom), defaultValue: 1.0);

    public static readonly StyledProperty<double> OffsetProperty =
        AvaloniaProperty.Register<ImageMapControl, double>(nameof(Offset), defaultValue: 0.0);

    public static readonly StyledProperty<Address?> SelectedAddressProperty =
        AvaloniaProperty.Register<ImageMapControl, Address?>(nameof(SelectedAddress), defaultValue: null);

    public static readonly StyledProperty<bool> LogarithmicViewProperty =
        AvaloniaProperty.Register<ImageMapControl, bool>(nameof(LogarithmicView), defaultValue: false);

    public static readonly StyledProperty<double> FontSizeProperty =
        AvaloniaProperty.Register<ImageMapControl, double>(nameof(FontSize), defaultValue: 8.0);

    public static readonly StyledProperty<IBrush?> CodeColorProperty =
        AvaloniaProperty.Register<ImageMapControl, IBrush?>(nameof(CodeColor), 
            defaultValue: new SolidColorBrush(Color.Parse("#FFB6C1"))); // Pale blue

    public static readonly StyledProperty<IBrush?> DataColorProperty =
        AvaloniaProperty.Register<ImageMapControl, IBrush?>(nameof(DataColor),
            defaultValue: new SolidColorBrush(Color.Parse("#ADD8E6"))); // Pale pink

    public static readonly StyledProperty<IBrush?> SegmentSeparatorColorProperty =
        AvaloniaProperty.Register<ImageMapControl, IBrush?>(nameof(SegmentSeparatorColor),
            defaultValue: Brushes.Black);

    public static readonly StyledProperty<IBrush?> BackgroundProperty =
        AvaloniaProperty.Register<ImageMapControl, IBrush?>(nameof(Background), defaultValue: Brushes.White);

    private List<SegmentLayout> segmentLayouts = [];
    private double contentWidth;


    public SegmentMap? SegmentMap
    {
        get => GetValue(SegmentMapProperty);
        set => SetValue(SegmentMapProperty, value);
    }

    public ImageMap? ImageMap
    {
        get => GetValue(ImageMapProperty);
        set => SetValue(ImageMapProperty, value);
    }

    public double Zoom
    {
        get => GetValue(ZoomProperty);
        set => SetValue(ZoomProperty, Math.Max(1.0, value));
    }

    public double Offset
    {
        get => GetValue(OffsetProperty);
        set => SetValue(OffsetProperty, Math.Max(0.0, value));
    }

    public bool LogarithmicView
    {
        get => GetValue(LogarithmicViewProperty);
        set => SetValue(LogarithmicViewProperty, value);
    }

    /// <summary>
    /// Font size to use when rendering segment names.
    /// </summary>
    public double FontSize
    {
        get => GetValue(FontSizeProperty);
        set => SetValue(FontSizeProperty, Math.Max(1.0, value));
    }

    /// <summary>
    /// Color to use when rendering executable code items.
    /// </summary>
    public IBrush? CodeColor
    {
        get => GetValue(CodeColorProperty);
        set => SetValue(CodeColorProperty, value);
    }

    /// <summary>
    /// Color to use when rendering data items.
    /// </summary>
    public IBrush? DataColor
    {
        get => GetValue(DataColorProperty);
        set => SetValue(DataColorProperty, value);
    }

    /// <summary>
    /// Color to use for segment separator lines.
    /// </summary>
    public IBrush? SegmentSeparatorColor
    {
        get => GetValue(SegmentSeparatorColorProperty);
        set => SetValue(SegmentSeparatorColorProperty, value);
    }

    /// <summary>
    /// The currently selected address.
    /// </summary>
    public Address? SelectedAddress
    {
        get => GetValue(SelectedAddressProperty);
        set => SetValue(SelectedAddressProperty, value);
    }

    /// <summary>
    /// Background color.
    /// </summary>
    public IBrush? Background
    {
        get => GetValue(BackgroundProperty);
        set => SetValue(BackgroundProperty, value);
    }

    public ImageMapControl()
    {
        Focusable = true;
        AffectsRender<ImageMapControl>(SegmentMapProperty, ImageMapProperty, ZoomProperty, OffsetProperty, LogarithmicViewProperty, FontSizeProperty);
        this.KeyDown += OnKeyDown;
        this.PointerWheelChanged += OnMouseWheel;
        this.PointerPressed += OnPointerPressed;
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        var oldZoom = Zoom;
        if (e.Key == Key.OemPlus || e.Key == Key.Add)
        {
            Zoom *= 1.2; // Zoom in - increase zoom factor
            e.Handled = true;
        }
        else if (e.Key == Key.OemMinus || e.Key == Key.Subtract)
        {
            Zoom /= 1.2; // Zoom out - decrease zoom factor
            e.Handled = true;
        }

        if (e.Handled)
            AdjustOffsetForZoom(oldZoom, Zoom);
    }

    private void OnMouseWheel(object? sender, PointerWheelEventArgs e)
    {
        var oldZoom = Zoom;
        if (e.Delta.Y > 0)
            Zoom *= 1.2; // Zoom in - increase zoom factor
        else
            Zoom /= 1.2; // Zoom out - decrease zoom factor
        e.Handled = true;

        AdjustOffsetForZoom(oldZoom, Zoom);
    }

    private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        // Give focus to this control so it can receive keyboard events
        this.Focus();
        
        var point = e.GetCurrentPoint(this);
        var pixelX = point.Position.X + Offset;
        var pixelY = point.Position.Y;

        // Find which segment was clicked
        foreach (var layout in this.segmentLayouts)
        {
            if (pixelX >= layout.PixelStart && pixelX < layout.PixelEnd)
            {
                var offsetWithinSegment = (uint)((pixelX - layout.PixelStart) / layout.PixelsPerByte);
                offsetWithinSegment = Math.Min(offsetWithinSegment, layout.Segment.Size - 1);
                SelectedAddress = layout.Segment.Address + offsetWithinSegment;
                ItemClicked?.Invoke(this, new ImageMapClickEventArgs(layout.Segment, offsetWithinSegment));
                e.Handled = true;
                break;
            }
        }
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var bounds = Bounds;
        if (bounds.Width <= 0 || bounds.Height <= 0 || SegmentMap is null || SegmentMap.Segments.Count == 0)
            return;

        // Calculate layout for current zoom
        var layoutResult = BuildLayouts(bounds.Width, Zoom);
        this.segmentLayouts = layoutResult.Layouts;
        this.contentWidth = layoutResult.ContentWidth;

        // Ensure offset is clamped to content width
        var maxOffset = Math.Max(0, this.contentWidth - bounds.Width);
        if (Offset > maxOffset)
            Offset = maxOffset;

        // Draw background
        context.FillRectangle(Background as IBrush ?? Brushes.White, bounds);

        // Draw segments and items
        double currentX = -Offset;
        foreach (var layout in this.segmentLayouts)
        {
            DrawSegment(context, layout, currentX, bounds.Height);
            currentX += layout.PixelWidth + SeparatorWidth;
        }
    }

    private (List<SegmentLayout> Layouts, double ContentWidth) BuildLayouts(double clientWidth, double zoom)
    {
        var layouts = new List<SegmentLayout>();

        if (SegmentMap is null || SegmentMap.Segments.Count == 0 || clientWidth <= 0)
            return (layouts, 0);

        var segments = SegmentMap.Segments.Values;

        // Calculate total size for width calculation
        double totalSize = LogarithmicView
            ? segments.Sum(s => Math.Log10(Math.Max(1, s.Size)))
            : segments.Sum(s => (double)s.Size);

        // Calculate available width for segments (exclude separators)
        double separatorTotal = (segments.Count - 1) * SeparatorWidth;
        double availableWidth = Math.Max(1, clientWidth - separatorTotal);
        double pixelPerUnit = availableWidth / totalSize;

        double pixelStart = 0;

        foreach (var segment in segments)
        {
            double segmentSize = LogarithmicView ? Math.Log10(Math.Max(1, segment.Size)) : segment.Size;
            double pixelWidth = segmentSize * pixelPerUnit * zoom;

            var layout = new SegmentLayout
            {
                Segment = segment,
                PixelStart = pixelStart,
                PixelWidth = pixelWidth,
                PixelsPerByte = pixelWidth / segment.Size
            };
            layout.PixelEnd = pixelStart + pixelWidth;

            layouts.Add(layout);
            pixelStart = layout.PixelEnd + SeparatorWidth;
        }

        double contentWidth = Math.Max(0, pixelStart - SeparatorWidth);
        return (layouts, contentWidth);
    }

    private double? ComputePixelPosition(List<SegmentLayout> layouts, Address address)
    {
        foreach (var layout in layouts)
        {
            var segStart = layout.Segment.Address;
            var segEnd = layout.Segment.Address + layout.Segment.Size;
            if (address >= segStart && address < segEnd)
            {
                var offset = address - segStart;
                return layout.PixelStart + offset * layout.PixelsPerByte;
            }
        }
        return null;
    }

    private void AdjustOffsetForZoom(double oldZoom, double newZoom)
    {
        if (Bounds.Width <= 0 || SegmentMap is null || SegmentMap.Segments.Count == 0 || SelectedAddress is null)
            return;

        var oldLayoutsResult = BuildLayouts(Bounds.Width, oldZoom);
        var newLayoutsResult = BuildLayouts(Bounds.Width, newZoom);

        var oldPos = ComputePixelPosition(oldLayoutsResult.Layouts, SelectedAddress.Value);
        var newPos = ComputePixelPosition(newLayoutsResult.Layouts, SelectedAddress.Value);
        if (oldPos is null || newPos is null)
            return;

        // Keep the selected address at the same screen position after zoom
        var currentScreenPos = oldPos.Value - Offset;
        var desiredOffset = newPos.Value - currentScreenPos;

        var maxOffset = Math.Max(0, newLayoutsResult.ContentWidth - Bounds.Width);
        Offset = Math.Max(0, Math.Min(desiredOffset, maxOffset));
    }

    private void DrawSegment(DrawingContext context, SegmentLayout layout, double x, double clientHeight)
    {
        // Draw segment background (uncovered area in grey)
        var segmentRect = new Rect(x, 0, layout.PixelWidth, clientHeight);
        context.FillRectangle(new SolidColorBrush(Color.Parse("#606060")), segmentRect);

        // Draw items within segment
        if (ImageMap is not null)
        {
            var itemsInSegment = ImageMap.Items.Values
                .Where(i => i.Address >= layout.Segment.Address &&
                            i.Address + i.Size <= layout.Segment.Address + layout.Segment.Size)
                .ToList();

            foreach (var item in itemsInSegment)
            {
                var offsetStart = item.Address - layout.Segment.Address;
                var pixelStart = x + offsetStart * layout.PixelsPerByte;
                var pixelWidth = item.Size * layout.PixelsPerByte;

                var itemRect = new Rect(pixelStart, 0, Math.Max(1, pixelWidth), clientHeight);
                var brush = GetColorForItem(item);
                if (brush is not null)
                {
                    context.FillRectangle(brush, itemRect);
                }
            }
        }

        // Draw segment name at bottom-left with shadow effect
        var typeface = new Typeface("monospace");
        
        var textX = Math.Max(x, x + 2);
        var textY = clientHeight - FontSize - 2;
        
        // Draw shadow/outline in off-white
        var shadowText = new FormattedText(
            layout.Segment.Name,
            System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            typeface,
            FontSize,
            new SolidColorBrush(Color.Parse("#F5F5F5")));
        context.DrawText(shadowText, new Point(textX, textY));
        
        // Draw main text offset by 0.5 pixels
        var mainText = new FormattedText(
            layout.Segment.Name,
            System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            typeface,
            FontSize,
            Brushes.Black);
        context.DrawText(mainText, new Point(textX + 0.5, textY + 0.5));

        // Draw separator line
        context.DrawLine(
            new Pen(SegmentSeparatorColor ?? Brushes.Black, SeparatorWidth),
            new Point(x + layout.PixelWidth, 0),
            new Point(x + layout.PixelWidth, clientHeight));
    }

    private IBrush? GetColorForItem(ImageMapItem item)
    {
        if (item is ImageMapVectorTable)
            return DataColor;
        if (item.DataType is UnknownType)
        {
            if (item.DataType.Size > 0)
                return DataColor;
            else
                return null;
        }
        if (item is ImageMapBlock)
            return CodeColor;
        else
            return DataColor;
    }

    public double GetMaxZoom()
    {
        if (SegmentMap is null || SegmentMap.Segments.Count == 0)
            return 1.0;

        var segments = SegmentMap.Segments.Values;
        double totalSize = 0;
        
        if (LogarithmicView)
            totalSize = segments.Sum(s => Math.Log10(Math.Max(1, s.Size)));
        else
            totalSize = segments.Sum(s => (double)s.Size);

        // The max zoom is when the total pixel width equals client width
        // pixelWidth = (totalSize * pixelPerUnit) / maxZoom
        // We want: pixelWidth * (count - 1) + totalSize / maxZoom = clientWidth
        // Solving: maxZoom = totalSize / (clientWidth - separators)
        
        // For now, return a reasonable value
        return Math.Max(1.0, totalSize / 100.0);
    }

    private class SegmentLayout
    {
        public required ImageSegment Segment { get; set; }
        public double PixelStart { get; set; }
        public double PixelEnd { get; set; }
        public double PixelWidth { get; set; }
        public double PixelsPerByte { get; set; }
    }
}

/// <summary>
/// Event arguments for when a byte/pixel is clicked in the ImageMapControl
/// </summary>
public class ImageMapClickEventArgs : EventArgs
{
    public ImageSegment Segment { get; set; }
    public uint OffsetWithinSegment { get; set; }

    public ImageMapClickEventArgs(ImageSegment segment, uint offsetWithinSegment)
    {
        Segment = segment;
        OffsetWithinSegment = offsetWithinSegment;
    }
}
