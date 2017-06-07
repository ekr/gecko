# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# apt-get install libnss3-dev libnspr4-dev
# npm install gyp

#
# gyp --depth=. --generator-output=obj
# cd obj; make

{
  'targets': [
      {
     'target_name': 'server',
     'type': 'executable',
      'cflags': [ '-g', ],
      'sources': [
       'sample/server.c',
      ],
     'dependencies': [
       'mozquic.gyp:mozquic',
      ],
     'libraries': [
       '<!@(pkg-config --libs nss)',
      ],
     },
      {
     'target_name': 'client',
     'type': 'executable',
      'cflags': [ '-g', ],
      'sources': [
       'sample/client.c',
      ],
     'dependencies': [
       'mozquic.gyp:mozquic',
      ],
     'libraries': [
       '<!@(pkg-config --libs nss)',
      ],
     },
   ],
}

