"""Public profile URL templates used by the username presence check.

This registry checks public profile URLs only. It does not identify the person
behind an account or collect private account information.
"""
USERNAME_PLATFORMS = {
    "GitHub": ("https://github.com/{u}", None),
    "LinkedIn": ("https://www.linkedin.com/in/{u}", None),
    "GitLab": ("https://gitlab.com/{u}", None),
    "Reddit": ("https://www.reddit.com/user/{u}", None),
    "Twitter/X": ("https://x.com/{u}", None),
    "Instagram": ("https://www.instagram.com/{u}/", None),
    "TikTok": ("https://www.tiktok.com/@{u}", None),
    "YouTube": ("https://www.youtube.com/@{u}", None),
    "Twitch": ("https://www.twitch.tv/{u}", None),
    "Pinterest": ("https://www.pinterest.com/{u}/", None),
    "Medium": ("https://medium.com/@{u}", None),
    "DEV Community": ("https://dev.to/{u}", None),
    "Steam": ("https://steamcommunity.com/id/{u}", "The specified profile could not be found"),
    "HackerNews": ("https://news.ycombinator.com/user?id={u}", "No such user"),
    "Keybase": ("https://keybase.io/{u}", None),
    "Telegram": ("https://t.me/{u}", None),
    "Facebook": ("https://www.facebook.com/{u}", None),
    "SoundCloud": ("https://soundcloud.com/{u}", None),
    "Spotify": ("https://open.spotify.com/user/{u}", None),
    "Roblox": ("https://www.roblox.com/user.aspx?username={u}", "Page cannot be found"),
    "Docker Hub": ("https://hub.docker.com/u/{u}", None),
}
