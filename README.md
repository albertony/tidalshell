# TidalShell

Unofficial PowerShell wrapper of the [Tidal](https://tidal.com/) REST API.
The main objective for now is to have a test bench for exploring the features
of the API, not an extremely robust and efficient interface.

---
WARNING:

The script is no longer able to login to Tidal, since Tidal changed to pure
OAuth token based authentication some time late 2019.

There are some reports of the existing login still working with specific tokens, so you *may* get it to work by sniffing a valid token using [Fiddler](https://www.telerik.com/download/fiddler), as described on [Python Tidal API](https://github.com/lucaslg26/TidalAPI), and save that in the $TidalToken global variable.

There is a description of the new login process over at [Music Player Daemon (MPD) forum](https://github.com/MusicPlayerDaemon/MPD/issues/545#issuecomment-506217706), but it
seems to require being granted access to Tidal's official developer portal (developer.tidal.com), where you have to create your own refresh token, client id and client secret.
Source code of other unofficial clients such as [Strawberry Music Player](https://github.com/strawberrymusicplayer/strawberry/blob/master/src/tidal/tidalservice.cpp), [node.js Tidal API](https://github.com/lucaslg26/TidalAPI/blob/master/lib/client.js) and [Python Tidal API](https://github.com/tamland/python-tidal/blob/master/tidalapi/__init__.py) may contain more clues.

---

See also [blushell](https://github.com/albertony/blushell),
PowerShell wrapper for the API of the BluOS music management system.


# Sources

Other unofficial Tidal API wrappers:

* https://github.com/lucaslg26/TidalAPI
* https://github.com/datagutt/WiMP-api
* http://pythonhosted.org/tidalapi/_modules/tidalapi.html

Spotify's WebAPI, which is similar in structure:

* https://developer.spotify.com/web-api/

