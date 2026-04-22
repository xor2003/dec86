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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reko.Core.Output;

/// <summary>
/// Utilities for formatting times and time-related values.
/// </summary>
public static class TimeUtilities
{
    private static readonly (double value, string suffix)[] timeSuffixes = new[]
    {
        (1.0, "s"),
        (1e-3, "ms"),
        (1e-6, "µs"),
        (1e-9, "ns"),
    };

    /// <summary>
    /// Renders the rate of units per second in a human-readable format.
    /// using appropriate time suffixes (e.g., "s", "ms", "µs", "ns")
    /// based on the magnitude of the rate.
    /// </summary>
    /// <param name="units">Number of units</param>
    /// <param name="elapsedTime">Time span for all the items to be completed.</param>
    /// <returns>A formatted string for the rate of units.</returns>
    public static string Rate(double units, TimeSpan elapsedTime)
    {
        var rate = units / elapsedTime.TotalSeconds;
        var arate = Math.Abs(rate);
        for (int i = 0; i < timeSuffixes.Length;++i)
        {
            var (limit, suffix) = timeSuffixes[i];
            if (arate >= limit)
            {
                return $"{rate / limit:0.###}/{suffix}";
            }
        }
        return $"<1/ns";
    }

    /// <summary>
    /// Renders the average interval per second in a human-readable format.
    /// using appropriate time suffixes (e.g., "s", "ms", "µs", "ns")
    /// based on the magnitude of the rate.
    /// </summary>
    /// <param name="units">Number of units</param>
    /// <param name="elapsedTime">Time span for all the items to be completed.</param>
    /// <returns>A formatted string for the rate of units.</returns>
    public static string AverageInterval(double units, TimeSpan elapsedTime)
    {
        if (units <= double.Epsilon)
            return "N/A";
        var rate = elapsedTime.TotalSeconds / units;
        var arate = Math.Abs(rate);
        for (int i = timeSuffixes.Length - 1; i > 0; --i)
        {
            var (limit, suffix) = timeSuffixes[i];
            if (arate >= limit)
            {
                return $"{rate / limit:0.###}{suffix}";
            }
        }
        return $"{rate:0.###}s";
    }

    /// <summary>
    /// Displays a time interval with an appropriate ISO suffix.
    /// </summary>
    /// <param name="elapsed">Elapsed time to render.</param>
    /// <returns>The rendered time.</returns>
    public static string Time(TimeSpan elapsed)
    {
        var time = elapsed.TotalSeconds;
        var atime = Math.Abs(time);
        foreach (var (limit, suffix) in timeSuffixes)
        {
            if (atime >= limit)
            {
                return $"{time / limit:0.###}{suffix}";
            }
        }
        return "<1ns";
    }
}
