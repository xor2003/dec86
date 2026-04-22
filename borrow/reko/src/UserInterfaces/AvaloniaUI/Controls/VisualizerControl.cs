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
using Avalonia.Media.Immutable;
using Reko.Core;
using Reko.Core.Memory;
using Reko.Gui.Visualizers;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Reko.UserInterfaces.AvaloniaUI.Controls;

/// <summary>
/// Custom control that visualizes bytes with colors.
/// </summary>
public class VisualizerControl : Control
{
    private static readonly TraceSwitch trace = new TraceSwitch(nameof(VisualizerControl), "Trace events in VisualizerControl", "Warning");

    public static readonly StyledProperty<ByteMemoryArea?> BytesProperty =
        AvaloniaProperty.Register<VisualizerControl, ByteMemoryArea?>(nameof(Bytes), defaultValue: null);

    public static readonly StyledProperty<int> LineWidthProperty =
        AvaloniaProperty.Register<VisualizerControl, int>(nameof(LineWidth), defaultValue: 16,
            coerce: (o, v) => Math.Max(1, v));

    public static readonly StyledProperty<int> ZoomProperty =
        AvaloniaProperty.Register<VisualizerControl, int>(nameof(Zoom), defaultValue: 2,
            coerce: (o, v) => Math.Max(1, v));

    public static readonly StyledProperty<Color[]?> HeatmapColorsProperty =
        AvaloniaProperty.Register<VisualizerControl, Color[]?>(nameof(HeatmapColors),
            defaultValue: CreateDefaultColorPalette());

    public static readonly DirectProperty<VisualizerControl, Visualizer?> VisualizerProperty =
        AvaloniaProperty.RegisterDirect<VisualizerControl, Visualizer?>(
            nameof(Visualizer),
            o => o.Visualizer,
            (o, v) => o.Visualizer = v);

    public static readonly DirectProperty<VisualizerControl, Program?> ProgramProperty =
        AvaloniaProperty.RegisterDirect<VisualizerControl, Program?>(
            nameof(Program),
            o => o.Program,
            (o, v) => o.Program = v);

    /// <summary>
    /// The visualizer to use to render the contents of the control.
    /// </summary>
    public Visualizer? Visualizer
    {
        get => visualizer;
        set
        {
            if (this.visualizer == value)
                return;
            this.visualizer = value;
            OnVisualizerChanged();
        }
    }
    private Visualizer? visualizer;

    public static readonly StyledProperty<int?> SelectedByteIndexProperty =
        AvaloniaProperty.Register<VisualizerControl, int?>(nameof(SelectedByteIndex), defaultValue: null);

    public static readonly StyledProperty<Point?> ConnectionPointProperty =
        AvaloniaProperty.Register<VisualizerControl, Point?>(nameof(ConnectionPoint), defaultValue: null);


    /// <summary>
    /// The bytes to render.
    /// </summary>
    public ByteMemoryArea? Bytes
    {
        get => GetValue(BytesProperty);
        set => SetValue(BytesProperty, value);
    }

    /// <summary>
    /// Minimum "chunk size" to use when rendering bytes.
    /// </summary>
    public int LineWidth
    {
        get => GetValue(LineWidthProperty);
        set => SetValue(LineWidthProperty, value);
    }

    /// <summary>
    /// Zoom factor to use when rendering bytes.
    /// </summary>
    public int Zoom
    {
        get => GetValue(ZoomProperty);
        set => SetValue(ZoomProperty, value);
    }

    /// <summary>
    /// Program being rendered.
    /// </summary>
    public Program? Program
    {
        get => this.program;
        set
        {
            if (this.program == value)
                return;
            this.program = value;
            OnProgramChanged();
        }
    }
    private Program? program;

    public Color[]? HeatmapColors
    {
        get => GetValue(HeatmapColorsProperty);
        set => SetValue(HeatmapColorsProperty, value);
    }

    public int? SelectedByteIndex
    {
        get => GetValue(SelectedByteIndexProperty);
        set => SetValue(SelectedByteIndexProperty, value);
    }

    public Point? ConnectionPoint
    {
        get => GetValue(ConnectionPointProperty);
        set => SetValue(ConnectionPointProperty, value);
    }

    public event EventHandler<ByteClickedEventArgs>? ByteClicked;

    static VisualizerControl()
    {
        AffectsRender<VisualizerControl>(BytesProperty, LineWidthProperty, ZoomProperty,
            HeatmapColorsProperty, SelectedByteIndexProperty, ConnectionPointProperty);
        AffectsMeasure<VisualizerControl>(BytesProperty, LineWidthProperty, ZoomProperty);
    }

    public VisualizerControl()
    {
        ClipToBounds = true;
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        if (Bytes == null || Bytes.Length == 0)
            return new Size(0, 0);

        var patchSize = Zoom;
        var lineWidth = LineWidth;

        // Calculate effective line width based on available space
        // Use multiples of LineWidth to fill available width
        int effectiveLineWidth = lineWidth;
        if (!double.IsInfinity(availableSize.Width))
        {
            int patchesPerRow = (int) (availableSize.Width / patchSize);
            if (patchesPerRow > lineWidth)
            {
                // Round down to nearest multiple of LineWidth
                effectiveLineWidth = (patchesPerRow / lineWidth) * lineWidth;
            }
        }

        var width = effectiveLineWidth * patchSize;
        var lines = (int) Math.Ceiling((double) Bytes.Length / effectiveLineWidth);
        var height = lines * patchSize;

        return new Size(width, height);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        if (Bytes is null || Bytes.Length == 0 || HeatmapColors is null)
            return;

        var patchSize = Zoom;
        var lineWidth = LineWidth;

        // Calculate effective line width based on actual control width
        int effectiveLineWidth = lineWidth;
        var controlWidth = Bounds.Width;
        if (controlWidth > 0)
        {
            int patchesPerRow = (int) (controlWidth / patchSize);
            if (patchesPerRow > lineWidth)
            {
                // Round down to nearest multiple of LineWidth
                effectiveLineWidth = (patchesPerRow / lineWidth) * lineWidth;
            }
        }

        if (this.visualizer is not null && program is not null)
        {
            var aiColors = this.visualizer.RenderBuffer(program, Bytes, Bytes.BaseAddress, Bytes.Bytes.Length, null);
            for (int i = 0; i < aiColors.Length; ++i)
            {
                var c = aiColors[i];
                var color = Color.FromRgb((byte) (c >> 16), (byte) (c >> 8), (byte) (c >> 0));
                var brush = new ImmutableSolidColorBrush(color);

                var x = (i % effectiveLineWidth) * patchSize;
                var y = (i / effectiveLineWidth) * patchSize;

                var rect = new Rect(x, y, patchSize, patchSize);
                context.DrawRectangle(brush, null, rect);
            }
        }
        else
        {
            // Render each byte as a colored patch
            for (int i = 0; i < Bytes.Length; i++)
            {
                var byteValue = Bytes.Bytes[i];
                var color = HeatmapColors[byteValue];
                var brush = new ImmutableSolidColorBrush(color);

                var x = (i % effectiveLineWidth) * patchSize;
                var y = (i / effectiveLineWidth) * patchSize;

                var rect = new Rect(x, y, patchSize, patchSize);
                context.DrawRectangle(brush, null, rect);
            }
        }

        // Draw highlight if a byte is selected
        if (SelectedByteIndex.HasValue && SelectedByteIndex.Value >= 0 &&
            SelectedByteIndex.Value < Bytes.Length)
        {
            var idx = SelectedByteIndex.Value;
            var x = (idx % effectiveLineWidth) * patchSize;
            var y = (idx / effectiveLineWidth) * patchSize;

            var rect = new Rect(x, y, patchSize, patchSize);
            var pen = new Pen(Brushes.White, 1);
            context.DrawRectangle(null, pen, rect);

            // Draw connection line to gutter if connection point is set
            if (ConnectionPoint.HasValue)
            {
                DrawConnectionLine(context,
                    new Point(x + patchSize / 2.0, y + patchSize / 2.0),
                    ConnectionPoint.Value);
            }
        }
    }

    private void DrawConnectionLine(DrawingContext context, Point patchCenter, Point gutterPoint)
    {
        var pen = new Pen(Brushes.White, 1);
        var points = new List<Point>();

        // Create path with only 90-degree bends
        // Simple approach: go horizontal first, then vertical
        var midX = (patchCenter.X + gutterPoint.X) / 2;

        points.Add(patchCenter);
        points.Add(new Point(midX, patchCenter.Y));
        points.Add(new Point(midX, gutterPoint.Y));
        points.Add(gutterPoint);

        // Draw line segments
        for (int i = 0; i < points.Count - 1; i++)
        {
            context.DrawLine(pen, points[i], points[i + 1]);
        }
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);

        if (Bytes == null || Bytes.Length == 0)
            return;

        var patchSize = Zoom;
        var lineWidth = LineWidth;
        var controlWidth = Bounds.Width;

        // Calculate effective line width
        int effectiveLineWidth = lineWidth;
        if (controlWidth > 0)
        {
            int patchesPerRow = (int) (controlWidth / patchSize);
            if (patchesPerRow > lineWidth)
            {
                effectiveLineWidth = (patchesPerRow / lineWidth) * lineWidth;
            }
        }

        var pos = e.GetPosition(this);
        var x = (int) (pos.X / patchSize);
        var y = (int) (pos.Y / patchSize);

        if (0 <= x && x < effectiveLineWidth)
        {
            var index = y * effectiveLineWidth + x;
            if (index >= 0 && index < Bytes.Length)
            {
                ByteClicked?.Invoke(this, new ByteClickedEventArgs(index));
            }
        }
    }

    protected virtual void OnVisualizerChanged()
    {
        if (visualizer is null)
        {
            LineWidth = 16;
        }
        else
        {
            this.LineWidth = visualizer.DefaultLineLength;
            this.Zoom = visualizer.DefaultZoom;
        }
        this.InvalidateVisual();
    }

    protected virtual void OnProgramChanged()
    {
        this.InvalidateVisual();
    }

    private static Color[] CreateDefaultColorPalette()
    {
        var colors = new Color[256];
        colors[0] = Color.FromRgb(0, 0, 0); // Black for 0

        // Create a gradient from dark blue -> cyan -> green -> yellow -> orange -> red
        for (int i = 1; i < 256; i++)
        {
            var t = i / 255.0;

            if (t < 0.2) // Dark blue to blue
            {
                var local = t / 0.2;
                colors[i] = Color.FromRgb(0, 0, (byte) (64 + local * 127));
            }
            else if (t < 0.4) // Blue to cyan
            {
                var local = (t - 0.2) / 0.2;
                colors[i] = Color.FromRgb(0, (byte) (local * 191), 191);
            }
            else if (t < 0.6) // Cyan to green
            {
                var local = (t - 0.4) / 0.2;
                colors[i] = Color.FromRgb(0, 191, (byte) (191 - local * 127));
            }
            else if (t < 0.8) // Green to yellow
            {
                var local = (t - 0.6) / 0.2;
                colors[i] = Color.FromRgb((byte) (local * 223), 191, (byte) (64 - local * 64));
            }
            else // Yellow to red
            {
                var local = (t - 0.8) / 0.2;
                colors[i] = Color.FromRgb(223, (byte) (191 - local * 95), 0);
            }
        }

        return colors;
    }
}

public class ByteClickedEventArgs : EventArgs
{
    public int ByteIndex { get; }

    public ByteClickedEventArgs(int byteIndex)
    {
        ByteIndex = byteIndex;
    }
}
