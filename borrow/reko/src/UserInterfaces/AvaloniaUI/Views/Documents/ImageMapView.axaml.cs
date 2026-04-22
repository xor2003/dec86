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
using Avalonia.Markup.Xaml;
using Reko.Core;
using Reko.Core.Collections;
using Reko.UserInterfaces.AvaloniaUI.Controls;
using System;

namespace Reko.UserInterfaces.AvaloniaUI.Views.Documents;

public partial class ImageMapView : UserControl
{
    public static readonly StyledProperty<SegmentMap?> SegmentMapProperty =
        AvaloniaProperty.Register<ImageMapView, SegmentMap?>(nameof(SegmentMap), defaultValue: null);

    public static readonly StyledProperty<ImageMap?> ImageMapProperty =
        AvaloniaProperty.Register<ImageMapView, ImageMap?>(nameof(ImageMap), defaultValue: null);

    public static readonly StyledProperty<double> ZoomProperty =
        AvaloniaProperty.Register<ImageMapView, double>(nameof(Zoom), defaultValue: 1.0);

    public static readonly StyledProperty<double> OffsetProperty =
        AvaloniaProperty.Register<ImageMapView, double>(nameof(Offset), defaultValue: 0.0);

    public static readonly StyledProperty<bool> LogarithmicViewProperty =
        AvaloniaProperty.Register<ImageMapView, bool>(nameof(LogarithmicView), defaultValue: false);

    public static readonly StyledProperty<double> LabelFontSizeProperty =
        AvaloniaProperty.Register<ImageMapView, double>(nameof(LabelFontSize), defaultValue: 8.0);

    private ImageMapControl? _imageMapControl;
    private Button? _leftScrollButton;
    private Button? _rightScrollButton;
    private const double ScrollAmount = 50.0;

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

    public double LabelFontSize
    {
        get => GetValue(LabelFontSizeProperty);
        set => SetValue(LabelFontSizeProperty, Math.Max(1.0, value));
    }

    public ImageMapView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
        
        // Set DataContext to this control so bindings work
        this.DataContext = this;
        
        _imageMapControl = this.FindControl<ImageMapControl>("ImageMapControl");
        _leftScrollButton = this.FindControl<Button>("LeftScrollButton");
        _rightScrollButton = this.FindControl<Button>("RightScrollButton");

        if (_leftScrollButton != null)
        {
            _leftScrollButton.Click += (s, e) => ScrollLeft();
        }

        if (_rightScrollButton != null)
        {
            _rightScrollButton.Click += (s, e) => ScrollRight();
        }

        // Update scroll buttons visibility based on zoom and offset
        this.SizeChanged += (s, e) => UpdateScrollButtonStates();
        ZoomProperty.Changed.AddClassHandler<ImageMapView>((sender, e) =>
        {
            sender.UpdateScrollButtonStates();
        });
        OffsetProperty.Changed.AddClassHandler<ImageMapView>((sender, e) =>
        {
            sender.UpdateScrollButtonStates();
        });
    }

    private void ScrollLeft()
    {
        Offset = Math.Max(0, Offset - ScrollAmount);
    }

    private void ScrollRight()
    {
        if (_imageMapControl != null && SegmentMap != null && SegmentMap.Segments.Count > 0)
        {
            var maxOffset = _imageMapControl.GetMaxZoom() * Bounds.Width;
            Offset = Math.Min(maxOffset, Offset + ScrollAmount);
        }
    }

    private void UpdateScrollButtonStates()
    {
        if (_imageMapControl == null || SegmentMap == null || SegmentMap.Segments.Count == 0)
        {
            if (_leftScrollButton != null) _leftScrollButton.IsEnabled = false;
            if (_rightScrollButton != null) _rightScrollButton.IsEnabled = false;
            return;
        }

        // Check if all segments fit in the view
        var totalSize = 0.0;
        if (LogarithmicView)
        {
            foreach (var seg in SegmentMap.Segments.Values)
                totalSize += Math.Log10(Math.Max(1, seg.Size));
        }
        else
        {
            foreach (var seg in SegmentMap.Segments.Values)
                totalSize += seg.Size;
        }

        var separatorWidth = (SegmentMap.Segments.Count - 1) * 1.0;
        var requiredWidth = totalSize / Zoom + separatorWidth;
        var allFits = requiredWidth <= Bounds.Width;

        if (_leftScrollButton != null)
            _leftScrollButton.IsEnabled = !allFits && Offset > 0;

        if (_rightScrollButton != null)
            _rightScrollButton.IsEnabled = !allFits && Offset < (requiredWidth - Bounds.Width);
    }
}
