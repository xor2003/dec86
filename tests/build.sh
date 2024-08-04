#!/bin/sh -x
ls *.C | perl -pe 's!\.[Cc]$!!' | xargs -n1 -I'{}' dosbox -c "MOUNT C: ." -c "C:" -c "BUILD.BAT {}"

