// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// sshd_test_pw.c
// Wrapper to inject test password data for sshd PAM authentication
//
// This wrapper implements custom versions of getpwnam, getpwnam_r,
// getspnam and getspnam_r. These functions first call their real
// libc versions, then check if the requested user matches test user
// specified in env variable TEST_USER and if so replace the password
// with crypted() value of TEST_PASSWD env variable.
//
// Compile:
// gcc -Wall -shared -o sshd_test_pw.so -fPIC sshd_test_pw.c
//
// Compile with debug:
// gcc -DVERBOSE -Wall -shared -o sshd_test_pw.so -fPIC sshd_test_pw.c
//
// Run sshd:
// LD_PRELOAD="sshd_test_pw.so" TEST_USER="..." TEST_PASSWD="..." sshd ...

// +build ignore

#define _GNU_SOURCE
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <crypt.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>

#define MIN(a,b) ((a) <= (b) ? (a) : (b))

#ifdef VERBOSE
#define DEBUG(X...) fprintf(stderr, X)
#else
#define DEBUG(X...) while (0) { }
#endif

/* crypt() password */
static struct crypt_data pwhash_data;
static char *
pwhash(char *passwd) {
  char salt[21];
  pid_t pid = getpid();
  time_t now = time(NULL);
  
  sprintf(salt, "$6$%08x%08x$",
	  (int) now ^ ((int) pid >> 7 | (int) pid << 25),
	  (int) pid ^ ((int) now >> 15 | (int) now << 17));

  pwhash_data.initialized = 0;
  return crypt_r(passwd, salt, &pwhash_data);
}

/* Pointers to real functions in libc */
static struct passwd * (*real_getpwnam)(const char *) = NULL;
static int (*real_getpwnam_r)(const char *, struct passwd *, char *, size_t, struct passwd **) = NULL;
static struct spwd * (*real_getspnam)(const char *) = NULL;
static int (*real_getspnam_r)(const char *, struct spwd *, char *, size_t, struct spwd **) = NULL;

/* Cached test user and test password */
static char test_user[256];
static char *test_passwd_hash = NULL;

static void
init(void) {
  /* Fetch real libc function pointers */
  real_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
  real_getpwnam_r = dlsym(RTLD_NEXT, "getpwnam_r");
  real_getspnam = dlsym(RTLD_NEXT, "getspnam");
  real_getspnam_r = dlsym(RTLD_NEXT, "getspnam_r");
  
  /* Fetch test user and test password from env */
  test_user[0] = '\0';
  if (getenv("TEST_USER") != NULL)
    strncpy(test_user, getenv("TEST_USER"), sizeof(test_user));
  test_user[255] = '\0';

  if (getenv("TEST_PASSWD") != NULL)
    test_passwd_hash = pwhash(getenv("TEST_PASSWD"));

  DEBUG("sshd_test_pw init():\n");
  DEBUG("\treal_getpwnam: %p\n", real_getpwnam);
  DEBUG("\treal_getpwnam_r: %p\n", real_getpwnam_r);
  DEBUG("\treal_getspnam: %p\n", real_getspnam);
  DEBUG("\treal_getspnam_r: %p\n", real_getspnam_r);
  DEBUG("\tTEST_USER: '%s'\n", test_user);
  DEBUG("\tTEST_PASSWD: '%s'\n", getenv("TEST_PASSWD"));
  DEBUG("\tTEST_PASSWD_HASH: '%s'\n", test_passwd_hash);
}

static int
is_test_user(const char *name) {
  if (test_user != NULL && strcmp(test_user, name) == 0)
    return 1;
  return 0;
}

/* getpwnam */

static char _pw_passwd[256];
struct passwd *
getpwnam(const char *name) {
  struct passwd *pw;

  DEBUG("sshd_test_pw getpwnam(%s)\n", name);
  
  if (real_getpwnam == NULL)
    init();
  if ((pw = real_getpwnam(name)) == NULL)
    return NULL;

  if (is_test_user(name)) {
    strncpy(_pw_passwd, test_passwd_hash, sizeof(_pw_passwd));
    _pw_passwd[255] = '\0';
    pw->pw_passwd = _pw_passwd;
  }
  
  return pw;
}

/* getpwnam_r */

int
getpwnam_r(const char *name,
	   struct passwd *pwd,
	   char *buf,
	   size_t buflen,
	   struct passwd **result) {
  int r;
  char pw_name[256];
  char pw_gecos[256];
  char pw_dir[256];
  char pw_shell[256];
  size_t ofs, len;

  DEBUG("sshd_test_pw getpwnam_r(%s)\n", name);
  
  if (real_getpwnam_r == NULL)
    init();
  if ((r = real_getpwnam_r(name, pwd, buf, buflen, result)) != 0 || *result == NULL)
    return r;

  if (is_test_user(name)) {
    strncpy(pw_name, pwd->pw_name, sizeof(pw_name));
    pw_name[255] = '\0';
    strncpy(pw_gecos, pwd->pw_gecos, sizeof(pw_gecos));
    pw_gecos[255] = '\0';
    strncpy(pw_dir, pwd->pw_dir, sizeof(pw_dir));
    pw_dir[255] = '\0';
    strncpy(pw_shell, pwd->pw_shell, sizeof(pw_shell));
    pw_name[255] = '\0';

    ofs = 0;

    pwd->pw_name = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, pw_name, buflen - ofs);
      pwd->pw_name = &buf[ofs];
      len = MIN(strlen(pw_name), buflen - ofs);
      buf[ofs + len] = '\0';
      ofs += len + 1;
    }

    pwd->pw_passwd = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, test_passwd_hash, buflen - ofs);
      pwd->pw_passwd = &buf[ofs];
      len = MIN(strlen(test_passwd_hash), buflen - ofs);
      buf[ofs+len] = '\0';
      ofs += len + 1;
    }

    pwd->pw_gecos = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, pw_gecos, buflen - ofs);
      pwd->pw_gecos = &buf[ofs];
      len = MIN(strlen(pw_gecos), buflen - ofs);
      buf[ofs+len] = '\0';
      ofs += len + 1;
    }

    pwd->pw_dir = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, pw_dir, buflen - ofs);
      pwd->pw_dir = &buf[ofs];
      len = MIN(strlen(pw_dir), buflen - ofs);
      buf[ofs+len] = '\0';
      ofs += len + 1;
    }

    pwd->pw_shell = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, pw_shell, buflen - ofs);
      pwd->pw_shell = &buf[ofs];
      len = MIN(strlen(pw_shell), buflen - ofs);
      buf[ofs+len] = '\0';
      ofs += len + 1;
    }
  }
  
  return r;
}

/* getspnam */

static char _sp_pwd[256];
struct spwd *
getspnam(const char *name) {
  struct spwd *sp;

  DEBUG("sshd_test_pw getspnam(%s)\n", name);
  
  if (real_getspnam == NULL)
    init();
  if ((sp = real_getspnam(name)) == NULL)
    return NULL;

  if (is_test_user(name)) {
    strncpy(_sp_pwd, test_passwd_hash, sizeof(_sp_pwd));
    _sp_pwd[255] = '\0';
    sp->sp_pwdp = _sp_pwd;
  }
  
  return sp;
}

/* getspnam_r */

int
getspnam_r(const char *name,
	   struct spwd *spbuf,
	   char *buf,
	   size_t buflen,
	   struct spwd **spbufp) {
  int r;
  char sp_nam[256];
  size_t ofs, len;

  DEBUG("sshd_test_pw getspnam_r(%s)\n", name);
  
  if (real_getspnam_r == NULL)
    init();
  if ((r = real_getspnam_r(name, spbuf, buf, buflen, spbufp)) != 0)
    return r;

  if (is_test_user(name)) {
    ofs = 0;
    
    strncpy(sp_nam, spbuf->sp_namp, sizeof(sp_nam));
    sp_nam[255] = '\0';

    ofs = 0;

    spbuf->sp_namp = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, sp_nam, buflen - ofs);
      spbuf->sp_namp = &buf[ofs];
      len = MIN(strlen(sp_nam), buflen - ofs);
      buf[ofs + len] = '\0';
      ofs += len + 1;
    }

    spbuf->sp_pwdp = NULL;
    if (ofs < buflen) {
      strncpy(buf + ofs, test_passwd_hash, buflen - ofs);
      spbuf->sp_pwdp = &buf[ofs];
      len = MIN(strlen(test_passwd_hash), buflen - ofs);
      buf[ofs + len] = '\0';
      ofs += len + 1;
    }
  }
  
  return r;
}
