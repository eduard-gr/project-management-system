Mysql-direct library
--------------------

10-January-2002      ©Cristian Nicola

Installation:
-------------
 This is not a component so do *NOT* try to install it as a component. These are 
objects and they do need to be created/freed in an explicit manner.
Check the demo to see how to create/free them.
 This is a beta version which means there are no know bugs, but there may be.
 If you want to use ssl you will need to find/build openssl and you will need to
redistribute libeay32.dll and ssleay32.dll with your executable. 

Note: - ssl has not been tested with kylix. I would appreciate if anyone has time to 
build mysql 4.0 on linux and try to connect to it from kylix (yes i'm still working 
on that laptop so it will take me like forever to install/reinstall everything in order
to debug both windows and kylix - so for the moment i can *only* assume it works with
kylix)
      - i finally got some time to comment each function/procedure so please do check 
the source code for comments.

Licencing issues:
-----------------
10-January-2002      ©Cristian Nicola
Note:
 Mysql is copyright by MySQL AB. Refer to their site ( http://www.mysql.com )
for licencing issues.
 Zlib is copyright by Jean-loup Gailly and Mark Adler. Refer to their site for
licencing issues. ( http://www.info-zip.org/pub/infozip/zlib/ )

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

NOTES:
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. If you are using it for a commercial software it must be open source and
     it must include full source code of this library in an unaltered fashion
     or you would need to ask for permission to use it. This library will be
     considered donationware which means if you want to contribute with any money
     or hardware you are more than welcome.
  4. This notice may not be removed or altered from any source distribution.

  Cristian Nicola
  n_cristian@hotmail.com

If you use the mysqldirect library in a product, i would appreciate *not*
receiving lengthy legal documents to sign. The sources are provided
for free but without warranty of any kind.  The library has been
entirely written by Cristian Nicola after libmysql of MYSQL AB.
