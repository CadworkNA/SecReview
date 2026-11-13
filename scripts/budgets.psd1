# What SecReview may weigh and how long it may take. build.ps1 measures each of these on
# every build and fails when one is over (scripts\check-budgets.ps1).
#
# A limit is not a target. Each leaves room for a slow build machine and for ordinary growth,
# and is there to catch the change that doubles something without anyone noticing: a library
# pulled in whole, a check that waits on the network, an icon that polls. Raising a limit is a
# reviewed change to this file, with the reason in the pull request.
#
# In brackets: what was measured when the limit was last set (November 2026).
@{
    # Size, in megabytes.
    StagedFolderMB  = 92      # everything that is installed, without the list below (84.4)
    WindowProgramMB = 22      # SecReview.exe (17.4)
    HelperProgramMB = 12      # SecReviewCli.exe, the only program that runs elevated (9.6)
    MaliciousListMB = 25      # known-malicious.idx; it grows with the feed (11.4)
    SetupProgramMB  = 35      # the setup program people download (25.2)

    # Time, in milliseconds.
    HelperStartMs   = 500     # SecReviewCli --version, the best of three starts (25)
    ScanMs          = 20000   # SecReviewCli --report: every check, on the PC that builds (3 300)
    WindowMs        = 6000    # SecReview.exe --demo --screenshot: start, draw, save a picture, close (1 500)

    # The notification-area icon while it waits for its next scan. Build machines only.
    IconIdleCpuMs   = 250     # processor time used in 10 seconds of waiting (0)
    IconMemoryMB    = 50      # memory that is its own (6.9)
}
