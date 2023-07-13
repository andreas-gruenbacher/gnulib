/* Test whether a file has a rich access control list.

   Copyright (C) 2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Written by Paul Eggert, Andreas Grünbacher, and Bruno Haible.  */

/* Without this pragma, gcc 4.7.0 20120126 may suggest that the
   file_has_richacl function might be candidate for attribute 'const'  */
#if (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) || 4 < __GNUC__
# pragma GCC diagnostic ignored "-Wsuggest-attribute=const"
#endif

#include <config.h>

#include <errno.h>

#include "acl.h"

#if HAVE_SYS_XATTR_H
# include <sys/xattr.h>
#endif

#if HAVE_LINUX_XATTR_H
# include <linux/xattr.h>
#endif

/* Return 1 if NAME has a nontrivial rich access control list,
   0 if ACLs are not supported, or if NAME has no or only a base ACL,
   and -1 (setting errno) on error.  Note callers can determine
   if ACLs are not supported as errno is set in that case also.
   SB must be set to the stat buffer of NAME,
   obtained through stat() or lstat().  */

int
file_has_richacl (char const *name, struct stat const *sb)
{
#if USE_ACL && HAVE_GETXATTR

# ifndef XATTR_NAME_RICHACL
#  define XATTR_NAME_RICHACL "system.richacl"
# endif

  if (! S_ISLNK (sb->st_mode))
    {
      ssize_t ret;

      ret = getxattr (name, XATTR_NAME_RICHACL, NULL, 0);
      if (ret < 0 && errno == ENODATA)
	ret = 0;
      else if (ret > 0)
	return 1;

      if (ret < 0)
	return - acl_errno_valid (errno);
    }
#endif
  return 0;
}
