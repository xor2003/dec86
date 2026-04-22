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

using Reko.Core;
using Reko.Core.Configuration;
using Reko.Gui.Reactive;
using Reko.Gui.ViewModels.Tools;
using System.Collections.ObjectModel;
using System.Linq;

namespace Reko.Gui.ViewModels.Documents;

public class PlatformPropertiesViewModel : ChangeNotifyingObject
{
    private readonly UserDataViewModel userData;
    
    public PlatformPropertiesViewModel(UserDataViewModel userData, IConfigurationService configSvc)
    {
        this.userData = userData;
        this.Platforms = new ObservableCollection<PlatformDefinition>(
            new PlatformDefinition[] { new() { Description = "(None)", Name = null } }
            .Concat(
                configSvc.GetEnvironments().OrderBy(e => e.Description)));
    }

    public ObservableCollection<PlatformDefinition> Platforms { get; }


    public PlatformDefinition? SelectedPlatformDefinition
    {
        get => this.selectedPlatformDefinition;
        set
        {
            base.RaiseAndSetIfChanged(ref this.selectedPlatformDefinition, value);
            this.userData.Platform = value?.Name;
        }
    }
    private PlatformDefinition? selectedPlatformDefinition;
}
