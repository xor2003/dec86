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

using Reko.Core.Configuration;
using Reko.Gui.ViewModels;
using Reko.Gui.ViewModels.Documents;
using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace Reko.UserInterfaces.WindowsForms.Forms;

public partial class PlatformPropertiesView : UserControl, IWindowPane
{
    public PlatformPropertiesView()
    {
        InitializeComponent();
        this.ddlPlatforms.ValueMember = nameof(PlatformDefinition.Name);
        this.Load += PlatformPropertiesView_Load;
        this.ddlPlatforms.SelectedIndexChanged += ddlPlatforms_SelectedIndexChanged;
    }

    private void ddlPlatforms_SelectedIndexChanged(object sender, EventArgs e)
    {
        ViewModel.SelectedPlatformDefinition = (PlatformDefinition) ddlPlatforms.SelectedItem;
    }

    private void PlatformPropertiesView_Load(object sender, EventArgs e)
    {
        this.ddlPlatforms.SelectedIndex = 0;
    }

    public IWindowFrame Frame { get; set; }

    public PlatformPropertiesViewModel ViewModel
    {
        get => (PlatformPropertiesViewModel)DataContext;
        set
        {
            DataContext = value;
            CreateBindings();
        }
    }

    private void CreateBindings()
    {
        this.ddlPlatforms.DataSource = ViewModel.Platforms;
        this.ddlPlatforms.DisplayMember = nameof(PlatformDefinition.Description);

        this.ddlPlatforms.DataBindings.Add(
            nameof(ddlPlatforms.SelectedItem),
            ViewModel,
            nameof(ViewModel.SelectedPlatformDefinition)
        );
    }

    public void Close()
    {
    }

    public void SetSite(IServiceProvider services)
    {
    }

    object IWindowPane.CreateControl()
    {
        return this;
    }
}
