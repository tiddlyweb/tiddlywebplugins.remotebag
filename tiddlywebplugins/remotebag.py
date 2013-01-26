"""
Routines for accessing a remote URI as if it where
a remote bag of tiddlers, for use in a recipe. The
idea is that if the bag portion of a line in a recipe
is a URI, then we'll get whatever is on the other end
as if it were tiddlers, and then filter accordingly,
if the recipe line has a filter.

At first pass this is a way of federating bags on
disparate tiddlyweb servers, but one can imagine adapting
it to work with non tiddler or tiddlyweb things.
"""

import httplib2
import os
import re
import simplejson

from urlparse import urlparse

from tiddlyweb.store import StoreError, HOOKS
from tiddlyweb.specialbag import SpecialBagError
from tiddlyweb.model.policy import ForbiddenError
from tiddlyweb.model.tiddler import Tiddler
from tiddlyweb.util import pseudo_binary, sha
from tiddlyweb.web.util import encode_name
from tiddlyweb.serializer import Serializer

from tiddlywebplugins.utils import ensure_bag, get_store


TIDDLERS_PATTERN = re.compile(r'.*/(bags|recipes)/[^/]+/tiddlers$')
REMOTEURI_BAG = '_remotebag'
HTTP = None
WHITE_DOMAINS = None


def recipe_change_hook(store, recipe):
    """
    When a recipe is put, if a bag is_remote, create a
    tiddler in REMOTEURI_BAG.
    """
    for bag, _ in recipe.get_recipe():
        if is_remote(store.environ, bag, whiteforce=True):
            update_remoteuri_bag(store, bag)


def update_remoteuri_bag(store, uri):
    """
    Create a tiddler in REMOTEURI_BAG to indicate it has been whitelisted.
    """
    key = _remotebag_key(store.environ, uri)
    store.put(Tiddler(key, REMOTEURI_BAG))


HOOKS['recipe']['put'].append(recipe_change_hook)


def init(config):
    """
    Initialize the plugin: setting up necessary defaults and globals.
    """
    config['special_bag_detectors'].append(is_remote)

    if config.get('remotebag.use_memcache'):
        import memcache
        cache = memcache.Client(config.get('memcache_hosts',
            ['127.0.0.1:11211']))
    else:
        path = config.get('remotebag.cache_dir', '.cache')
        if not os.path.isabs(path):
            path = os.path.join(config.get('root_dir', ''), path)
        cache = path

    global HTTP
    HTTP = httplib2.Http(cache)

    store = get_store(config)
    policy = dict(manage=['NONE'], read=['NONE'], write=['NONE'],
            create=['NONE'], accept=['NONE'])
    ensure_bag(REMOTEURI_BAG, store, policy_dict=policy)


def is_remote(environ, uri, whiteforce=False):
    """
    Return the tool for retrieving remote if this is a remote bag.
    Otherwise None.
    """
    if uri.startswith('http:') or uri.startswith('https:'):

        if whiteforce or is_white(environ, uri):

            def curry(environ, func):
                def actor(bag):
                    return func(environ, bag)
                return actor

            return (curry(environ, get_remote_tiddlers),
                    curry(environ, get_remote_tiddler))

    return None


def is_white(environ, uri):
    """
    Return true if the URI passes a whitelist mechanism.
    Otherwise raise a ForbiddedError.
    """
    global WHITE_DOMAINS
    netloc = urlparse(uri)[1]

    if not WHITE_DOMAINS:
        whitelist = environ.get('tiddlyweb.config', {}).get(
                'remotebag.white_domains', [])
        patterns = []
        for domain in whitelist:
            pattern = domain.replace('.', r'\.')
            patterns.append(pattern)
        WHITE_DOMAINS = re.compile('(?:' + '|'.join(patterns) + ')$')

    if WHITE_DOMAINS.search(netloc) or via_recipe(environ, uri):
        return True
    raise ForbiddenError('remote uri not accepted: %s' % uri)


def _remotebag_key(environ, uri):
    """
    Generate a tiddler title to use as the key in the REMOTEURI_BAG.
    """
    server_host = environ.get('tiddlyweb.config', {}).get(
            'server_host')['host']
    return sha(uri + server_host).hexdigest()


def via_recipe(environ, uri):
    """
    Return true if this uri has been used in a recipe somewhere.
    """
    store = environ['tiddlyweb.store']
    key = _remotebag_key(environ, uri)
    try:
        tiddler = Tiddler(key, REMOTEURI_BAG)
        store.get(tiddler)
        return True
    except StoreError:
        raise ForbiddenError('remote uri not whitelisted: %s' % uri)


def retrieve_remote(uri, accept=None, method='GET'):
    """
    Do an http request to get the remote content.
    """
    uri = uri.encode('UTF-8')
    try:
        if accept:
            response, content = HTTP.request(uri, method=method,
                    headers={'Accept': accept})
        else:
            response, content = HTTP.request(uri, method=method)
    except httplib2.HttpLib2Error, exc:
        raise SpecialBagError('unable to retrieve remote: %s: %s'
                % (uri, exc))

    if response['status'] == '200' or response['status'] == '304':
        return response, content
    else:
        raise SpecialBagError('bad response from remote: %s: %s: %s'
                % (uri, response['status'], content))


def get_remote_tiddlers(environ, uri):
    """
    Retrieve the tiddlers at uri, yield as skinny tiddlers.
    """
    handler = _determine_remote_handler(environ, uri)[0]
    return handler(environ, uri)


def get_remote_tiddler(environ, tiddler):
    """
    Retrieve the tiddler from its remote location.
    """
    uri = tiddler.bag
    handler = _determine_remote_handler(environ, uri)[1]
    return handler(environ, uri, tiddler.title)


def get_remote_tiddlers_html(environ, uri):
    """
    Retrieve a page of HTML as a single yielded tiddler.
    """
    _, content = retrieve_remote(uri)
    try:
        title = content.split('<title>', 1)[1].split('</title>', 1)[0]
    except IndexError:
        title = uri
    yield RemoteTiddler(title, uri)


def get_remote_tiddler_html(environ, uri, title):
    """
    Retrieve a webpage as a tiddler. Type comes from
    content-type. Text is set to the body.
    TODO: use response metadata to set other attributes
    """
    response, content = retrieve_remote(uri)
    tiddler = RemoteTiddler(title, uri)
    try:
        content_type = response['content-type'].split(';', 1)[0]
    except KeyError:
        content_type = 'text/html'
    if pseudo_binary(content_type):
        tiddler.text = content.decode('utf-8', 'replace')
    else:
        tiddler.text = content
    tiddler.type = content_type
    return tiddler


def _get_tiddlyweb_tiddler(environ, uri, title):
    """
    Get a tiddler with title from uri.
    """
    url = uri + '/' + encode_name(title)
    _, content = retrieve_remote(url, accept='application/json')
    return _process_json_tiddler(environ, content, uri)


def _get_tiddlyweb_tiddlers(environ, uri):
    """
    Get the tiddlers at uri.
    """
    _, content = retrieve_remote(uri, accept='application/json')
    return _process_json_tiddlers(environ, content, uri)


def _test_uri_for_tiddlers(environ, uri):
    """
    Return true if uri looks like a bags or recipes tiddlers URI.
    """
    return TIDDLERS_PATTERN.search(uri)


TESTERS = [(_test_uri_for_tiddlers,
    (_get_tiddlyweb_tiddlers, _get_tiddlyweb_tiddler))]


def _determine_remote_handler(environ, uri):
    """
    Determine which remote handler to use for this uri.
    """
    config = environ['tiddlyweb.config']
    if len(TESTERS) == 1:
        TESTERS.extend(config.get('remotebag.remote_handlers', []))
    for tester, target in TESTERS:
        if tester(environ, uri):
            return target
    # do default, getting raw html
    return (get_remote_tiddlers_html, get_remote_tiddler_html)


def _process_json_tiddler(environ, content, uri):
    """
    Transmute JSON content into a Tiddler.
    """
    content = content.decode('utf-8')
    data = simplejson.loads(content)
    tiddler = RemoteTiddler(data['title'], uri)
    serializer = Serializer('json', environ)
    serializer.object = tiddler
    return serializer.from_string(content)


def _process_json_tiddlers(environ, content, uri):
    """
    Transmute JSON content into a yielding Tiddler collection.
    Set 'store' to avoid additional GETs later in processing.
    """
    try:
        data = simplejson.loads(content.decode('utf-8'))
    except ValueError, exc:
        raise SpecialBagError('unable to decode remote json content: %s' % exc)
    store = environ['tiddlyweb.store']

    for item in data:
        tiddler = RemoteTiddler(item['title'], uri)
        for key in ['creator', 'fields', 'created', 'modified',
                'modifier', 'type','tags']:
            try:
                setattr(tiddler, key, item[key])
            except (KeyError, AttributeError):
                pass
        tiddler.store = store
        yield tiddler

class RemoteTiddler(Tiddler):

    def __init__(self, title=None, bag=None):
        Tiddler.__init__(self, title, bag)
        self._text = None

    def get_text(self):
        if self._text is None:
            try:
                self = self.store.get(self)
                self._text = self.text
            except (AttributeError, StoreError):
                return ''
        return self._text

    def set_text(self, value):
        self._text = value

    def del_text(self):
        self._text = None

    text = property(get_text, set_text, del_text, "Manage text attribute")
