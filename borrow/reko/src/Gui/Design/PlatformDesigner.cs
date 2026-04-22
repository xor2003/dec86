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
using Reko.Core.Services;
using Reko.Gui.Services;
using Reko.Gui.ViewModels.Tools;
using System;

namespace Reko.Gui.Design
{
    public class PlatformDesigner : TreeNodeDesigner
    {
        public override void Initialize(object obj)
        {
            base.Initialize(obj);
            SetTreeNodeProperties();
            var userData = GetUserData()!;
            userData.PropertyChanged += userData_PropertyChanged;
        }

        private void userData_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            var program = GetProgram();
            var userData = GetUserData();
            if (program is null || userData is null)
                return;
            if (program.Platform?.Name == userData.Platform)
                return;
            var cfgSvc = Services.RequireService<IConfigurationService>();
            program.Platform = cfgSvc.GetEnvironment(userData.Platform).Load(Services, program.Architecture);
            SetTreeNodeProperties();
        }

        public override void DoDefaultAction()
        {
            var userData = GetUserData();
            if (userData is null)
                return;
            var shellUiSvc = Services.RequireService<IDecompilerShellUiService>();
            var factory = Services.RequireService<IWindowPaneFactory>();
            var docType = GetType().FullName!;
            var windowFrame = shellUiSvc.FindDocumentWindow(docType, userData);
            if (windowFrame is null)
            {
                var pane = factory.CreatePlatformPropertiesPane(userData);
                windowFrame = shellUiSvc.CreateDocumentWindow(
                    docType,
                    userData,
                    "Platform properties",
                    pane);
            }
            windowFrame.Show();
        }

        private Program? GetProgram()
        {
            return (Program?)(this.Parent as ProgramDesigner)?.Component;
        }

        private UserDataViewModel? GetUserData()
        {
            return (this.Parent as ProgramDesigner)?.UserData;
        }

        private void SetTreeNodeProperties()
        {
            TreeNode!.Text = NodeText();
            TreeNode.ImageName = "Platform.ico";
            TreeNode.ToolTipText = null;
        }

        private string NodeText()
        {
            var defaultText = ((IPlatform) this.Component!).Description;
            var userData = GetUserData();
            if (userData?.Platform is null)
            {
                return defaultText;
            }
            var cfgSvc = Services.RequireService<IConfigurationService>();
            var def = cfgSvc.GetEnvironment(userData.Platform);
            if (def?.Description is null)
                return defaultText;
            return $"{def.Description} *";
        }
    }
}
