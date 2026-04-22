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
using Reko.Gui.ViewModels;
using Reko.Gui.ViewModels.Documents;
using Reko.Gui.ViewModels.Tools;

namespace Reko.Gui.Services
{
    /// <summary>
    /// This interface abstracts the creation of dialog and document windows between
    /// different GUI environments.
    /// </summary>
    public interface IWindowPaneFactory
    {
        IWindowPane CreateBaseAddressFinderPane(Program program);
        IWindowPane CreateHexDisassemblerPane();
        IWindowPane CreateSegmentListPane(Program program);
        IWindowPane CreateStructureEditorPane(Program program);
        ILowLevelViewInteractor CreateLowLevelViewPane(Program program);
        IWindowPane CreatePlatformPropertiesPane(UserDataViewModel userData);
    }
}
