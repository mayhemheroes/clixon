/*
 *
  ***** BEGIN LICENSE BLOCK *****
 
  Copyright (C) 2009-2019 Olof Hagsand
  Copyright (C) 2020 Olof Hagsand and Rubicon Communications, LLC(Netgate)

  This file is part of CLIXON.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Alternatively, the contents of this file may be used under the terms of
  the GNU General Public License Version 3 or later (the "GPL"),
  in which case the provisions of the GPL are applicable instead
  of those above. If you wish to allow use of your version of this file only
  under the terms of the GPL, and not to allow others to
  use your version of this file under the terms of Apache License version 2, 
  indicate your decision by deleting the provisions above and replace them with
  the  notice and other provisions required by the GPL. If you do not delete
  the provisions above, a recipient may use your version of this file under
  the terms of any one of the Apache License version 2 or the GPL.

  ***** END LICENSE BLOCK *****
 */

#ifdef HAVE_CONFIG_H
#include "clixon_config.h" /* generated by config & autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>
#include <syslog.h>       
#include <fcntl.h>

/* cligen */
#include <cligen/cligen.h>

/* clixon */
#include "clixon_err.h"
#include "clixon_string.h"
#include "clixon_queue.h"
#include "clixon_hash.h"
#include "clixon_handle.h"
#include "clixon_log.h"
#include "clixon_file.h"
#include "clixon_yang.h"
#include "clixon_xml.h"
#include "clixon_xml_sort.h"
#include "clixon_options.h"
#include "clixon_data.h"
#include "clixon_xpath_ctx.h"
#include "clixon_xpath.h"
#include "clixon_json.h"
#include "clixon_nacm.h"
#include "clixon_netconf_lib.h"
#include "clixon_yang_module.h"
#include "clixon_xml_map.h"
#include "clixon_xml_io.h"
#include "clixon_xml_nsctx.h"

#include "clixon_datastore.h"
#include "clixon_datastore_read.h"

#define handle(xh) (assert(text_handle_check(xh)==0),(struct text_handle *)(xh))

/*! Ensure that xt only has a single sub-element and that is "config" 
 */
static int
singleconfigroot(cxobj  *xt, 
		 cxobj **xp)
{
    int    retval = -1;
    cxobj *x = NULL;
    int    i = 0;

    /* There should only be one element and called config */
    x = NULL;
    while ((x = xml_child_each(xt, x,  CX_ELMNT)) != NULL){
	i++;
	if (strcmp(xml_name(x), "config")){
	    clicon_err(OE_DB, ENOENT, "Wrong top-element %s expected config", 
		       xml_name(x));
	    goto done;
	}
    }
    if (i != 1){
	clicon_err(OE_DB, ENOENT, "Top-element is not unique, expecting single  config");
	goto done;
    }
    x = NULL;
    while ((x = xml_child_each(xt, x,  CX_ELMNT)) != NULL){
	if (xml_rm(x) < 0)
	    goto done;
	if (xml_free(xt) < 0)
	    goto done;
	*xp = x;
	break;
    }
    retval = 0;
 done:
    return retval;
}
/*! Given XML tree x0 with marked nodes, copy marked nodes to new tree x1
 * Two marks are used: XML_FLAG_MARK and XML_FLAG_CHANGE
 *
 * The algorithm works as following:
 * (1) Copy individual nodes marked with XML_FLAG_CHANGE 
 * until nodes marked with XML_FLAG_MARK are reached, where 
 * (2) the complete subtree of that node is copied. 
 * (3) Special case: key nodes in lists are copied if any node in list is marked
 *  @note you may want to check:!yang_config(ys)
 */
static int
xml_copy_marked(cxobj *x0, 
		cxobj *x1)
{
    int        retval = -1;
    int        mark;
    cxobj     *x;
    cxobj     *xcopy;
    int        iskey;
    yang_stmt *yt;
    char      *name;
    char      *prefix;

    assert(x0 && x1);
    yt = xml_spec(x0); /* can be null */
    xml_spec_set(x1, yt);
   /* Copy prefix*/
    if ((prefix = xml_prefix(x0)) != NULL)
	if (xml_prefix_set(x1, prefix) < 0)
	    goto done;
    
    /* Copy all attributes */
    x = NULL;
    while ((x = xml_child_each(x0, x, CX_ATTR)) != NULL) {
	name = xml_name(x);
	if ((xcopy = xml_new(name, x1, CX_ATTR)) == NULL)
	    goto done;
	if (xml_copy(x, xcopy) < 0) 
	    goto done;
    }

    /* Go through children to detect any marked nodes:
     * (3) Special case: key nodes in lists are copied if any 
     * node in list is marked
     */
    mark = 0;
    x = NULL;
    while ((x = xml_child_each(x0, x, CX_ELMNT)) != NULL) {
	if (xml_flag(x, XML_FLAG_MARK|XML_FLAG_CHANGE)){
	    mark++;
	    break;
	}
    }
    x = NULL;
    while ((x = xml_child_each(x0, x, CX_ELMNT)) != NULL) {
	name = xml_name(x);
	if (xml_flag(x, XML_FLAG_MARK)){
	    /* (2) the complete subtree of that node is copied. */
	    if ((xcopy = xml_new(name, x1, CX_ELMNT)) == NULL)
		goto done;
	    if (xml_copy(x, xcopy) < 0) 
		goto done;
	    continue; 
	}
	if (xml_flag(x, XML_FLAG_CHANGE)){
	    /*  Copy individual nodes marked with XML_FLAG_CHANGE */
	    if ((xcopy = xml_new(name, x1, CX_ELMNT)) == NULL)
		goto done;
	    if (xml_copy_marked(x, xcopy) < 0) /*  */
		goto done;
	}
	/* (3) Special case: key nodes in lists are copied if any 
	 * node in list is marked */
	if (mark && yt && yang_keyword_get(yt) == Y_LIST){
	    /* XXX: I think yang_key_match is suboptimal here */
	    if ((iskey = yang_key_match(yt, name)) < 0)
		goto done;
	    if (iskey){
		if ((xcopy = xml_new(name, x1, CX_ELMNT)) == NULL)
		    goto done;
		if (xml_copy(x, xcopy) < 0) 
		    goto done;
	    }
	}
    }
    retval = 0;
 done:
    return retval;
}

/*! Read module-state in an XML tree
 *
 * @param[in]  th     Datastore text handle
 * @param[in]  yspec  Top-level yang spec 
 * @param[in]  xt     XML tree
 * @param[out] msdiff Modules-state differences
 *
 * The modstate difference contains:
 * - if there is a modstate
 * - the modstate identifier
 * - An entry for each modstate that differs marked with flag: ADD|DEL|CHANGE
 *
 * Algorithm:
 * Read mst (module-state-tree) from xml tree (if any) and compare it with 
 * the system state mst.
 * This can happen:
 * 1) There is no modules-state info in the file
 * 2) There is module state info in the file
 * 3) For each module state m in the file:
 *    3a) There is no such module in the system -> add to list mark as DEL
 *    3b) File module-state matches system
 *    3c) File module-state does not match system -> add to list mark as CHANGE
 * 4) For each module state s in the system
 *    4a) If there is no such module in the file -> add to list mark as ADD
 */
static int
text_read_modstate(clicon_handle       h,
		   yang_stmt          *yspec,
		   cxobj              *xt,
		   modstate_diff_t    *msdiff)
{
    int    retval = -1;
    cxobj *xmodfile = NULL;   /* modstate of system (loaded yang modules in runtime) */
    cxobj *xmodsystem = NULL; /* modstate of file, eg startup */
    cxobj *xf = NULL;         /* xml modstate in file */
    cxobj *xf2;               /* copy */
    cxobj *xs;                /* xml modstate in system */
    cxobj *xs2;               /* copy */
    char  *name;              /* module name */
    char  *frev;              /* file revision */
    char  *srev;              /* system revision */

    /* Read module-state as computed at startup, see startup_module_state() */
    xmodsystem = clicon_modst_cache_get(h, 1);
    if ((xmodfile = xml_find_type(xt, NULL, "modules-state", CX_ELMNT)) == NULL){
	/* 1) There is no modules-state info in the file */
    }
    else if (xmodsystem && msdiff){
	msdiff->md_status = 1;  /* There is module state in the file */
	/* Create modstate tree for this file */
	if (clixon_xml_parse_string("<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"/>",
				    YB_MODULE, yspec, &msdiff->md_diff, NULL) < 0)
	    goto done;
	if (xml_rootchild(msdiff->md_diff, 0, &msdiff->md_diff) < 0) 
	    goto done;

	/* 3) For each module state m in the file */
	xf = NULL;
	while ((xf = xml_child_each(xmodfile, xf, CX_ELMNT)) != NULL) {
	    if (strcmp(xml_name(xf), "module-set-id") == 0){
		if (xml_body(xf) && (msdiff->md_set_id = strdup(xml_body(xf))) == NULL){
		    clicon_err(OE_UNIX, errno, "strdup");
		    goto done;
		}
	    }
	    if (strcmp(xml_name(xf), "module"))
		continue; /* ignore other tags, such as module-set-id */
	    if ((name = xml_find_body(xf, "name")) == NULL)
		continue;
	    /* 3a) There is no such module in the system */
	    if ((xs = xpath_first(xmodsystem, NULL, "module[name=\"%s\"]", name)) == NULL){
		if ((xf2 = xml_dup(xf)) == NULL) 	  /* Make a copy of this modstate */
		    goto done;
		if (xml_addsub(msdiff->md_diff, xf2) < 0)   /* Add it to modstatediff */
		    goto done;
		xml_flag_set(xf2, XML_FLAG_DEL);
		continue;
	    }
	    /* These two shouldnt happen since revision is key, just ignore */
	    if ((frev = xml_find_body(xf, "revision")) == NULL)
		continue;
	    if ((srev = xml_find_body(xs, "revision")) == NULL)
		continue;
	    if (strcmp(frev, srev)!=0){
		/* 3c) File module-state does not match system */
		if ((xf2 = xml_dup(xf)) == NULL)
		    goto done;
		if (xml_addsub(msdiff->md_diff, xf2) < 0)
		    goto done;
		xml_flag_set(xf2, XML_FLAG_CHANGE);
	    }
	}
	/* 4) For each module state s in the system (xmodsystem) */
	xs = NULL;
	while ((xs = xml_child_each(xmodsystem, xs, CX_ELMNT)) != NULL) {
	    if (strcmp(xml_name(xs), "module"))
		continue; /* ignore other tags, such as module-set-id */
	    if ((name = xml_find_body(xs, "name")) == NULL)
		continue;
	    /* 4a) If there is no such module in the file -> add to list mark as ADD */	    
	    if ((xf = xpath_first(xmodfile, NULL, "module[name=\"%s\"]", name)) == NULL){
		if ((xs2 = xml_dup(xs)) == NULL) 	  /* Make a copy of this modstate */
		    goto done;
		if (xml_addsub(msdiff->md_diff, xs2) < 0)   /* Add it to modstatediff */
		    goto done;
		xml_flag_set(xs2, XML_FLAG_ADD);
		continue;
	    }
	}
    }
    /* The module-state is removed from the input XML tree. This is done
     * in all cases, whether CLICON_XMLDB_MODSTATE is on or not.
     * Clixon systems with CLICON_XMLDB_MODSTATE disabled ignores it
     */
    if (xmodfile){ 	
	if (xml_purge(xmodfile) < 0)
	    goto done;
    }
    retval = 0;
 done:
    return retval;
}

/*! Common read function that reads an XML tree from file
 * @param[in]  th    Datastore text handle
 * @param[in]  db    Symbolic database name, eg "candidate", "running"
 * @param[in]  yspec Top-level yang spec
 * @param[out] xp    XML tree read from file
 * @param[out] msdiff    If set, return modules-state differences
 */
int
xmldb_readfile(clicon_handle      h,
	       const char         *db,
	       yang_stmt          *yspec,
	       cxobj             **xp,
	       modstate_diff_t    *msdiff)
{
    int    retval = -1;
    cxobj *x0 = NULL;
    char  *dbfile = NULL;
    int    fd = -1;
    char  *format;
    int    ret;
    
    if (xmldb_db2file(h, db, &dbfile) < 0)
	goto done;
    if (dbfile==NULL){
	clicon_err(OE_XML, 0, "dbfile NULL");
	goto done;
    }
    if ((format = clicon_option_str(h, "CLICON_XMLDB_FORMAT")) == NULL){
	clicon_err(OE_CFG, ENOENT, "No CLICON_XMLDB_FORMAT");
	goto done;
    }
    /* Parse file into internal XML tree from different formats */
    if ((fd = open(dbfile, O_RDONLY)) < 0) {
	clicon_err(OE_UNIX, errno, "open(%s)", dbfile);
	goto done;
    }    
    if (strcmp(format, "json")==0){
	if ((ret = clixon_json_parse_file(fd, YB_MODULE, yspec, &x0, NULL)) < 0) /* XXX: ret == 0*/
	    goto done;
    }
    else if ((clixon_xml_parse_file(fd, YB_MODULE, yspec, "</config>", &x0, NULL)) < 0)
	goto done;

    /* Always assert a top-level called "config". 
       To ensure that, deal with two cases:
       1. File is empty <top/> -> rename top-level to "config" */
    if (xml_child_nr(x0) == 0){ 
	if (xml_name_set(x0, "config") < 0)
	    goto done;     
    }
    /* 2. File is not empty <top><config>...</config></top> -> replace root */
    else{ 
	/* There should only be one element and called config */
	if (singleconfigroot(x0, &x0) < 0)
	    goto done;
    }
    /* From Clixon 3.10,datastore files may contain module-state defining
     * which modules are used in the file. 
     */
    if (text_read_modstate(h, yspec, x0, msdiff) < 0)
	goto done;
    if (xp){
	*xp = x0;
	x0 = NULL;
    }
    retval = 0;
 done:
    if (fd != -1)
	close(fd);
    if (dbfile)
	free(dbfile);
    if (x0)
	xml_free(x0);
    return retval;
}

/*! Get content of database using xpath. return a set of matching sub-trees
 * The function returns a minimal tree that includes all sub-trees that match
 * xpath.
 * This is a clixon datastore plugin of the the xmldb api
 * @param[in]  h      Clicon handle
 * @param[in]  db     Name of database to search in (filename including dir path
 * @param[in]  nsc    External XML namespace context, or NULL
 * @param[in]  xpath  String with XPATH syntax. or NULL for all
 * @param[out] xret   Single return XML tree. Free with xml_free()
 * @param[out] msdiff    If set, return modules-state differences
 * @retval     0      OK
 * @retval     -1     Error
 * @see xmldb_get  the generic API function
 */
static int
xmldb_get_nocache(clicon_handle       h,
		  const char         *db, 
		  cvec               *nsc,
		  char               *xpath,
		  cxobj             **xtop,
		  modstate_diff_t    *msdiff)
{
    int             retval = -1;
    char           *dbfile = NULL;
    yang_stmt      *yspec;
    cxobj          *xt = NULL;
    cxobj          *x;
    int             fd = -1;
    cxobj         **xvec = NULL;
    size_t          xlen;
    int             i;

    if ((yspec = clicon_dbspec_yang(h)) == NULL){
	clicon_err(OE_YANG, ENOENT, "No yang spec");
	goto done;
    }
    if (xmldb_readfile(h, db, yspec, &xt, msdiff) < 0)
	goto done;
    /* Here xt looks like: <config>...</config> */
    /* Given the xpath, return a vector of matches in xvec */
    if (xpath_vec(xt, nsc, "%s", &xvec, &xlen, xpath?xpath:"/") < 0)
	goto done;

    /* If vectors are specified then mark the nodes found with all ancestors
     * and filter out everything else,
     * otherwise return complete tree.
     */
    if (xvec != NULL)
	for (i=0; i<xlen; i++){
	    x = xvec[i];
	    xml_flag_set(x, XML_FLAG_MARK);
	}
    /* Remove everything that is not marked */
    if (!xml_flag(xt, XML_FLAG_MARK))
	if (xml_tree_prune_flagged_sub(xt, XML_FLAG_MARK, 1, NULL) < 0)
	    goto done;
    /* reset flag */
    if (xml_apply(xt, CX_ELMNT, (xml_applyfn_t*)xml_flag_reset, (void*)XML_FLAG_MARK) < 0)
	goto done;

    /* Add default values (if not set) */
    if (xml_default_recurse(xt) < 0)
    	goto done;
#if 0 /* debug */
    if (xml_apply0(xt, -1, xml_sort_verify, NULL) < 0)
	clicon_log(LOG_NOTICE, "%s: sort verify failed #2", __FUNCTION__);
#endif
    if (clicon_debug_get()>1)
    	clicon_xml2file(stderr, xt, 0, 1);
    *xtop = xt;
    xt = NULL;
    retval = 0;
 done:
    if (xt)
	xml_free(xt);
    if (dbfile)
	free(dbfile);
    if (xvec)
	free(xvec);
    if (fd != -1)
	close(fd);
    return retval;
}

/*! Get content of database using xpath. return a set of matching sub-trees
 * The function returns a minimal tree that includes all sub-trees that match
 * xpath.
 * This is a clixon datastore plugin of the the xmldb api
 * @param[in]  h      Clicon handle
 * @param[in]  db     Name of database to search in (filename including dir path
 * @param[in]  nsc    External XML namespace context, or NULL
 * @param[in]  xpath  String with XPATH syntax. or NULL for all
 * @param[out] xret   Single return XML tree. Free with xml_free()
 * @param[out] msdiff    If set, return modules-state differences
 * @retval     0      OK
 * @retval     -1     Error
 * @see xmldb_get  the generic API function
 */
static int
xmldb_get_cache(clicon_handle    h,
		const char      *db, 
		cvec            *nsc,
		char            *xpath,
		cxobj          **xtop,
		modstate_diff_t *msdiff)
{
    int             retval = -1;
    yang_stmt      *yspec;
    cxobj          *x0t = NULL; /* (cached) top of tree */
    cxobj          *x0;
    cxobj         **xvec = NULL;
    size_t          xlen;
    int             i;
    db_elmnt       *de = NULL;
    cxobj          *x1t = NULL;
    db_elmnt        de0 = {0,};

    if ((yspec = clicon_dbspec_yang(h)) == NULL){
	clicon_err(OE_YANG, ENOENT, "No yang spec");
	goto done;
    }
    de = clicon_db_elmnt_get(h, db);
    if (de == NULL || de->de_xml == NULL){ /* Cache miss, read XML from file */
	/* If there is no xml x0 tree (in cache), then read it from file */
	if (xmldb_readfile(h, db, yspec, &x0t, msdiff) < 0)
	    goto done;
	/* XXX: should we validate file if read from disk? 
	 * Argument against: we may want to have a semantically wrong file and wish
	 * to edit?
	 */
	de0.de_xml = x0t;
	clicon_db_elmnt_set(h, db, &de0);
    } /* x0t == NULL */
    else
	x0t = de->de_xml;
    /* Here x0t looks like: <config>...</config> */
    /* Given the xpath, return a vector of matches in xvec 
     * Can we do everything in one go?
     * 0) Make a new tree
     * 1) make the xpath check 
     * 2) iterate thru matches (maybe this can be folded into the xpath_vec?)
     *   a) for every node that is found, copy to new tree
     *   b) if config dont dont state data
     */

    /* Here xt looks like: <config>...</config> */
    if (xpath_vec(x0t, nsc, "%s", &xvec, &xlen, xpath?xpath:"/") < 0)
	goto done;

    /* Make new tree by copying top-of-tree from x0t to x1t */
    if ((x1t = xml_new(xml_name(x0t), NULL, CX_ELMNT)) == NULL)
	goto done;
    xml_spec_set(x1t, xml_spec(x0t));

    /* Iterate through the match vector
     * For every node found in x0, mark the tree up to t1
     */
    for (i=0; i<xlen; i++){
	x0 = xvec[i];
	xml_flag_set(x0, XML_FLAG_MARK);
	xml_apply_ancestor(x0, (xml_applyfn_t*)xml_flag_set, (void*)XML_FLAG_CHANGE);
    }
    if (xml_copy_marked(x0t, x1t) < 0) /* config */
	goto done;
    if (xml_apply(x0t, CX_ELMNT, (xml_applyfn_t*)xml_flag_reset, (void*)(XML_FLAG_MARK|XML_FLAG_CHANGE)) < 0)
	goto done;
    if (xml_apply(x1t, CX_ELMNT, (xml_applyfn_t*)xml_flag_reset, (void*)(XML_FLAG_MARK|XML_FLAG_CHANGE)) < 0)
	goto done;
    /* x1t is wrong here should be <config><system>.. but is <system>.. */
    /* XXX where should we apply default values once? */
    if (xml_default_recurse(x1t) < 0)
	goto done;
    /* Copy the matching parts of the (relevant) XML tree.
     * If cache was empty, also update to datastore cache
     */
    if (clicon_debug_get()>1)
    	clicon_xml2file(stderr, x1t, 0, 1);
    *xtop = x1t;
    retval = 0;
 done:
    clicon_debug(1, "%s retval:%d", __FUNCTION__, retval);
    if (xvec)
	free(xvec);
    return retval;
}

/*! Get the raw cache of whole tree
 * Useful for some higer level usecases for optimized access
 * This is a clixon datastore plugin of the the xmldb api
 * @param[in]  h      Clicon handle
 * @param[in]  db     Name of database to search in (filename including dir path
 * @param[in]  nsc    External XML namespace context, or NULL
 * @param[in]  xpath  String with XPATH syntax. or NULL for all
 * @param[in]  config If set only configuration data, else also state
 * @param[out] xret   Single return XML tree. Free with xml_free()
 * @param[out] msdiff    If set, return modules-state differences
 * @retval     0      OK
 * @retval     -1     Error
 */
static int
xmldb_get_zerocopy(clicon_handle    h,
		   const char      *db, 
		   cvec            *nsc,
		   char            *xpath,
		   cxobj          **xtop,
		   modstate_diff_t *msdiff)
{
    int             retval = -1;
    yang_stmt      *yspec;
    cxobj          *x0t = NULL; /* (cached) top of tree */
    cxobj         **xvec = NULL;
    size_t          xlen;
    int             i;
    cxobj          *x0;
    db_elmnt       *de = NULL;
    db_elmnt        de0 = {0,};

    if ((yspec = clicon_dbspec_yang(h)) == NULL){
	clicon_err(OE_YANG, ENOENT, "No yang spec");
	goto done;
    }
    de = clicon_db_elmnt_get(h, db);
    if (de == NULL || de->de_xml == NULL){ /* Cache miss, read XML from file */
	/* If there is no xml x0 tree (in cache), then read it from file */
	if (xmldb_readfile(h, db, yspec, &x0t, msdiff) < 0)
	    goto done;
	/* XXX: should we validate file if read from disk? 
	 * Argument against: we may want to have a semantically wrong file and wish
	 * to edit?
	 */
	de0.de_xml = x0t;
	clicon_db_elmnt_set(h, db, &de0);
    } /* x0t == NULL */
    else
	x0t = de->de_xml;
    /* Here xt looks like: <config>...</config> */
    if (xpath_vec(x0t, nsc, "%s", &xvec, &xlen, xpath?xpath:"/") < 0)
	goto done;
    /* Iterate through the match vector
     * For every node found in x0, mark the tree up to t1
     */
    for (i=0; i<xlen; i++){
	x0 = xvec[i];
	xml_flag_set(x0, XML_FLAG_MARK);
	xml_apply_ancestor(x0, (xml_applyfn_t*)xml_flag_set, (void*)XML_FLAG_CHANGE);
    }
    /* Apply default values (removed in clear function) */
    if (xml_default_recurse(x0t) < 0)
	goto done;
    if (clicon_debug_get()>1)
    	clicon_xml2file(stderr, x0t, 0, 1);
    *xtop = x0t;
    retval = 0;
 done:
    clicon_debug(1, "%s retval:%d", __FUNCTION__, retval);
    if (xvec)
	free(xvec);
    return retval;
}

/*! Get content of datastore and return a copy of the XML tree
 * @param[in]  h      Clicon handle
 * @param[in]  db     Name of database to search in, eg "running"
 * @param[in]  nsc    XML namespace context for XPATH
 * @param[in]  xpath  String with XPATH syntax. or NULL for all
 * @param[out] xret   Single return XML tree. Free with xml_free()
 * @retval     0      OK
 * @retval     -1     Error
 * @code
 *   if (xmldb_get(xh, "running", NULL, "/interfaces/interface[name="eth"]", &xt) < 0)
 *      err;
 *   xml_free(xt);
 * @endcode
 * @see xmldb_get0  Underlying more capable API for enabling zero-copy
 */
int 
xmldb_get(clicon_handle    h, 
	  const char      *db, 
	  cvec            *nsc,
	  char            *xpath,
	  cxobj          **xret)
{
    return xmldb_get0(h, db, nsc, xpath, 1, xret, NULL);
}

/*! Zero-copy variant of get content of database
 *
 * The function returns a minimal tree that includes all sub-trees that match
 * xpath. 
 * It can be used for zero-copying if CLICON_DATASTORE_CACHE is set
 * appropriately.
 * The tree returned may be the actual cache, therefore calls for cleaning and
 * freeing tree must be made after use.
 * @param[in]  h      Clicon handle
 * @param[in]  db     Name of datastore, eg "running"
 * @param[in]  nsc    External XML namespace context, or NULL
 * @param[in]  xpath  String with XPATH syntax. or NULL for all
 * @param[in]  copy   Force copy. Overrides cache_zerocopy -> cache 
 * @param[out] xret   Single return XML tree. Free with xml_free()
 * @param[out] msdiff    If set, return modules-state differences (upgrade code)
 * @retval     0      OK
 * @retval     -1     Error
 * @code
 *   cxobj   *xt;
 *   if (xmldb_get0(xh, "running", nsc, "/interface[name="eth"]", 0, &xt, NULL) < 0)
 *      err;
 *   ...
 *   xmldb_get0_clear(h, xt);   # Clear tree from default values and flags 
 *   xmldb_get0_free(h, &xt);   # Free tree
 * @endcode
 * @see xml_nsctx_node  to get a XML namespace context from XML tree
 * @see xmldb_get for a copy version (old-style)
 */
int 
xmldb_get0(clicon_handle    h, 
	   const char      *db, 
	   cvec            *nsc,
	   char            *xpath,
	   int              copy,
	   cxobj          **xret,
	   modstate_diff_t *msdiff)
{
    int               retval = -1;

    switch (clicon_datastore_cache(h)){
    case DATASTORE_NOCACHE:
	/* Read from file into created/copy tree, prune non-matching xpath 
	 * Add default values in copy
	 * Copy deleted by xmldb_free
	 */
	retval = xmldb_get_nocache(h, db, nsc, xpath, xret, msdiff);
	break;
    case DATASTORE_CACHE_ZEROCOPY:
	/* Get cache (file if empty) mark xpath match in original tree 
	 * add default values in original tree and return that.
	 * Default values and markings removed in xmldb_clear
	 */
	if (!copy){
	    retval = xmldb_get_zerocopy(h, db, nsc, xpath, xret, msdiff);
	    break;
	}
	/* fall through */
    case DATASTORE_CACHE:
	/* Get cache (file if empty) mark xpath match and copy marked into copy 
	 * Add default values in copy, return copy
	 * Copy deleted by xmldb_free
	 */
	retval = xmldb_get_cache(h, db, nsc, xpath, xret, msdiff);
	break;
    }
    return retval;
}

/*! Clear cached xml tree obtained with xmldb_get0, if zerocopy
 *
 * @param[in]  h    Clicon handle
 * @param[in]  db   Name of datastore
 * "Clear" an xml tree means removing default values and resetting all flags.
 * @see xmldb_get0
 */
int 
xmldb_get0_clear(clicon_handle    h, 
		 cxobj           *x)
{
    int        retval = -1;
    
    if (x == NULL)
	goto ok;
    /* clear XML tree of defaults */
    if (xml_tree_prune_flagged(x, XML_FLAG_DEFAULT, 1) < 0)
	goto done;
    /* clear mark and change */
    xml_apply0(x, CX_ELMNT, (xml_applyfn_t*)xml_flag_reset,
	       (void*)(0xff));
 ok:
    retval = 0;
 done:
    return retval;
}

/*! Free xml tree obtained with xmldb_get0
 * @param[in]     h   Clixon handle
 * @param[in,out] xp  Pointer to XML cache. 
 * @see xmldb_get0
 */
int 
xmldb_get0_free(clicon_handle    h, 
	       cxobj          **xp)
{
    if (*xp == NULL)
	return 0;
    if (clicon_datastore_cache(h) != DATASTORE_CACHE_ZEROCOPY)
	xml_free(*xp);
    *xp = NULL;
    return 0;
}
