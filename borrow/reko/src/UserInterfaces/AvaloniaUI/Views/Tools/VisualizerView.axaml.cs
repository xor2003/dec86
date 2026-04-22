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
using Avalonia.Media;
using Reko.Core.Memory;
using Reko.Gui;
using Reko.Gui.Visualizers;
using Reko.UserInterfaces.AvaloniaUI.Controls;
using System;
using System.Collections.ObjectModel;

namespace Reko.UserInterfaces.AvaloniaUI.Views.Tools
{
    public partial class VisualizerView : UserControl
    {
        public VisualizerView()
        {
            InitializeComponent();
            InitializeControls();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

    }
    public partial class VisualizerView : UserControl
    {
        public static readonly StyledProperty<byte[]?> BytesProperty =
            AvaloniaProperty.Register<VisualizerControl, byte[]?>(nameof(Bytes), defaultValue: null);

        public static readonly StyledProperty<int> LineWidthProperty =
            AvaloniaProperty.Register<VisualizerControl, int>(nameof(LineWidth), defaultValue: 32);

        public static readonly StyledProperty<int> ZoomProperty =
            AvaloniaProperty.Register<VisualizerControl, int>(nameof(Zoom), defaultValue: 2);

        public static readonly StyledProperty<Visualizer?> VisualizerProperty =
            AvaloniaProperty.Register<VisualizerControl, Visualizer?>(nameof(Visualizer), defaultValue: null);

        public static readonly StyledProperty<Color[]?> HeatmapColorsProperty =
            AvaloniaProperty.Register<VisualizerControl, Color[]?>(nameof(HeatmapColors), defaultValue: null);

        public static readonly StyledProperty<IBrush?> HeatmapBackgroundProperty =
            AvaloniaProperty.Register<VisualizerControl, IBrush?>(nameof(HeatmapBackground),
                defaultValue: Brushes.Black);

        private VisualizerControl? _visualizerControl;
        private ListBox? _gutterListBox;
        private Border? _gutterBorder;
        private ScrollViewer? _heatmapScrollViewer;
        private ObservableCollection<GutterLabel> _gutterLabels = new ObservableCollection<GutterLabel>();

        public byte[]? Bytes
        {
            get => GetValue(BytesProperty);
            set => SetValue(BytesProperty, value);
        }

        public int LineWidth
        {
            get => GetValue(LineWidthProperty);
            set => SetValue(LineWidthProperty, value);
        }

        public int Zoom
        {
            get => GetValue(ZoomProperty);
            set => SetValue(ZoomProperty, value);
        }

        public Color[]? HeatmapColors
        {
            get => GetValue(HeatmapColorsProperty);
            set => SetValue(HeatmapColorsProperty, value);
        }

        public IBrush? HeatmapBackground
        {
            get => GetValue(HeatmapBackgroundProperty);
            set => SetValue(HeatmapBackgroundProperty, value);
        }

        public ListOption? Visualizer
        {
            get => visualizer;
            set => this.visualizer = value;
        }
        private ListOption? visualizer;


        public event EventHandler<ByteClickedEventArgs>? ByteClicked;



        private void InitializeControls()
        {
            _visualizerControl = this.FindControl<VisualizerControl>("HeatmapView");
            _gutterListBox = this.FindControl<ListBox>("GutterListBox");
            _gutterBorder = this.FindControl<Border>("GutterBorder");
            _heatmapScrollViewer = this.FindControl<ScrollViewer>("HeatmapScrollViewer");

            if (_visualizerControl != null)
            {
                _visualizerControl.ByteClicked += OnByteClicked;
            }

            if (_gutterListBox != null)
            {
                _gutterListBox.ItemsSource = _gutterLabels;
                _gutterListBox.SelectionChanged += OnGutterSelectionChanged;
            }

            // Recalculate connection line on resize
            this.SizeChanged += (sender, e) =>
            {
                if (_gutterListBox?.SelectedItem is GutterLabel)
                {
                    UpdateConnectionLine();
                }
            };

            // Bind properties to HeatmapView
            BytesProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                if (sender._visualizerControl != null)
                    sender._visualizerControl.Bytes = e.NewValue as ByteMemoryArea;
            });

            LineWidthProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                if (sender._visualizerControl != null && e.NewValue is int width)
                    sender._visualizerControl.LineWidth = width;
            });

            ZoomProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                if (sender._visualizerControl != null && e.NewValue is int size)
                    sender._visualizerControl.Zoom = size;
            });

            VisualizerProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                if (sender._visualizerControl != null)
                    sender._visualizerControl.Visualizer = e.NewValue as Visualizer;
            });

            HeatmapColorsProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                var colors = e.NewValue as Color[];
                if (sender._visualizerControl != null && colors != null)
                    sender._visualizerControl.HeatmapColors = colors;
            });

            HeatmapBackgroundProperty.Changed.AddClassHandler<VisualizerView>((sender, e) =>
            {
                if (sender._heatmapScrollViewer != null)
                    sender._heatmapScrollViewer.Background = e.NewValue as IBrush;
            });

        }

        private void OnByteClicked(object? sender, ByteClickedEventArgs e)
        {
            ByteClicked?.Invoke(this, e);
        }

        private void OnGutterSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (_gutterListBox?.SelectedItem is GutterLabel label && _visualizerControl != null)
            {
                _visualizerControl.SelectedByteIndex = label.ByteOffset;
                UpdateConnectionLine();
                _visualizerControl.InvalidateVisual();
            }
        }

        private void UpdateConnectionLine()
        {
            if (_gutterListBox?.SelectedItem is not GutterLabel label || _visualizerControl == null)
                return;

            // Calculate connection point (1 pixel to the left of selected text, vertically centered)
            var selectedContainer = _gutterListBox.ContainerFromItem(label);
            if (selectedContainer is Control control)
            {
                var relativePos = control.TranslatePoint(new Point(0, control.Bounds.Height / 2), _visualizerControl);
                if (relativePos.HasValue)
                {
                    // Get the left edge of the gutter relative to heatmap view
                    var gutterPos = _gutterBorder?.TranslatePoint(new Point(-1, 0), _visualizerControl);
                    if (gutterPos.HasValue)
                    {
                        _visualizerControl.ConnectionPoint = new Point(gutterPos.Value.X, relativePos.Value.Y);
                    }
                }
            }
        }

        /// <summary>
        /// Add a label to the gutter
        /// </summary>
        public void AddGutterLabel(string text, int byteOffset)
        {
            _gutterLabels.Add(new GutterLabel { Label = text, ByteOffset = byteOffset });

            if (_gutterBorder != null)
                _gutterBorder.IsVisible = true;
        }

        /// <summary>
        /// Clear all gutter labels
        /// </summary>
        public void ClearGutterLabels()
        {
            _gutterLabels.Clear();

            if (_visualizerControl != null)
            {
                _visualizerControl.SelectedByteIndex = null;
                _visualizerControl.ConnectionPoint = null;
            }

            if (_gutterBorder != null)
                _gutterBorder.IsVisible = false;
        }
    }

    public class GutterLabel
    {
        public string Label { get; set; } = string.Empty;
        public int ByteOffset { get; set; }
    }
}
