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

using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Dock.Model.Core;
using Reko.Gui.ViewModels;
using Reko.UserInterfaces.AvaloniaUI.ViewModels;
using Reko.UserInterfaces.AvaloniaUI.ViewModels.Tools;
using System;
using System.Diagnostics;

namespace Reko.UserInterfaces.AvaloniaUI
{
    /// <summary>
    /// This class is used as a Data template to instantiate views from their
    /// corresponding view models. It assumes all view model classes names end
    /// with "...ViewModel" and the corresponding view models have the name
    /// ending with "...View".
    /// </summary>
    public class ViewLocator : IDataTemplate
    {
        public bool SupportsRecycling => false;

        /// <summary>
        /// Given a view model object <see cref="data"/>, creates an instance
        /// of the corresponding View class. 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public Control? Build(object? data)
        {
            if (data is null)
                return null;
            Type? type = DetermineViewType(data);

            if (type is { })
            {
                return (Control) Activator.CreateInstance(type)!;
            }
            else
            {
                return new TextBlock { Text = $"View not found for {data.GetType()}" };
            }
        }

        private Type? DetermineViewType(object? data)
        {
            if (data is null)
                return null;
            var name = data.GetType().FullName!.Replace("ViewModel", "View");
            var type = Type.GetType(name);
            return type;
        }

        public bool Match(object? data)
        {
            return data is ViewModelBase || data is IDockable || data is IWindowPane;
        }
    }
}
