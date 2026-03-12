/**
 * search-index.js – Full-text search index with n-gram fuzzy matching & relevance scoring.
 *
 * Builds an inverted index over library metadata (name, author, organization,
 * description, tags, public function names) and scores hits by field weight,
 * token-frequency, and match quality (exact > prefix > substring > n-gram).
 *
 * Usage:
 *   var SearchIndex = require('./lib/search-index');
 *   var idx = new SearchIndex();
 *   idx.addLibrary(lib);            // lib = installed_libs record or system lib object
 *   var results = idx.search('pipett', { tagFilters: ['liquid-handling'] });
 *   // results → [{ id: 'lib_id', score: 4.21, type: 'user' }, …]
 */

'use strict';

// ---- constants ---------------------------------------------------------------

/** Minimum n-gram length */
var NGRAM_MIN = 2;

/** Maximum n-gram length */
var NGRAM_MAX = 4;

/** How much each field contributes to the final score */
var FIELD_WEIGHTS = {
	name:          10,
	tag:            8,
	author:         6,
	organization:   5,
	description:    3,
	'function':     2
};

/** Score multiplier for quality of match within a field */
var MATCH_QUALITY = {
	exact:     4.0,   // query === token
	prefix:    3.0,   // token starts with query
	substring: 2.0,   // token contains query
	ngram:     1.0    // fuzzy n-gram overlap
};

/** Minimum n-gram overlap ratio (0-1) to consider a fuzzy match */
var NGRAM_THRESHOLD = 0.3;

// ---- helpers -----------------------------------------------------------------

/**
 * Tokenize a string into lowercase alphanumeric words.
 * Splits on whitespace and non-alphanum characters, removes empties.
 */
function tokenize(text) {
	if (!text || typeof text !== 'string') return [];
	return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
}

/**
 * Generate character n-grams for a word.
 * E.g. ngrams('hello', 2, 3) → ['he','el','ll','lo','hel','ell','llo']
 */
function ngrams(word, min, max) {
	var result = [];
	if (!word) return result;
	for (var n = min; n <= max; n++) {
		for (var i = 0; i <= word.length - n; i++) {
			result.push(word.substring(i, i + n));
		}
	}
	return result;
}

/**
 * Compute Dice coefficient overlap of two n-gram sets (arrays).
 * Dice = 2 * |intersection| / (|A| + |B|).  Returns 0-1.
 * Better than Jaccard for typo tolerance when set sizes differ.
 */
function ngramOverlap(aGrams, bGrams) {
	if (!aGrams.length || !bGrams.length) return 0;
	var setB = {};
	bGrams.forEach(function(g) { setB[g] = (setB[g] || 0) + 1; });
	var setBCopy = {};
	Object.keys(setB).forEach(function(k) { setBCopy[k] = setB[k]; });
	var intersection = 0;
	aGrams.forEach(function(g) {
		if (setBCopy[g] && setBCopy[g] > 0) {
			intersection++;
			setBCopy[g]--;
		}
	});
	return (aGrams.length + bGrams.length) > 0
		? (2 * intersection) / (aGrams.length + bGrams.length)
		: 0;
}

// ---- SearchIndex class -------------------------------------------------------

/**
 * @constructor
 */
function SearchIndex() {
	/**
	 * Forward store: id → { type, fields: { fieldName: [tokens] }, ngramSets: { fieldName: { token: [grams] } } }
	 */
	this._docs = {};

	/**
	 * Inverted index: token → [{ id, field }]
	 */
	this._index = {};

	/**
	 * N-gram inverted index: gram → Set-of-tokens (for fuzzy lookup)
	 */
	this._ngramIndex = {};
}

/**
 * Clear the entire index.
 */
SearchIndex.prototype.clear = function() {
	this._docs = {};
	this._index = {};
	this._ngramIndex = {};
};

/**
 * Remove a single document from the index.
 */
SearchIndex.prototype.removeLibrary = function(id) {
	var doc = this._docs[id];
	if (!doc) return;

	// Remove from inverted index
	var self = this;
	Object.keys(doc.fields).forEach(function(field) {
		doc.fields[field].forEach(function(token) {
			var postings = self._index[token];
			if (postings) {
				self._index[token] = postings.filter(function(p) { return p.id !== id; });
				if (self._index[token].length === 0) delete self._index[token];
			}
		});
	});

	delete this._docs[id];
};

/**
 * Add a library to the index.
 *
 * @param {object} lib  - Library record.  Expected fields:
 *   _id, library_name (or display_name/canonical_name for system libs),
 *   author, organization, description, tags[], public_functions[],
 *   resource_types[] (system libs only)
 * @param {string} [type='user']  - 'user' or 'system'
 * @param {string} [extraFnText] - Pre-built function-name string for system libs
 */
SearchIndex.prototype.addLibrary = function(lib, type, extraFnText) {
	if (!lib || !lib._id) return;
	type = type || 'user';

	// Remove old entry if re-indexing
	if (this._docs[lib._id]) this.removeLibrary(lib._id);

	var name = lib.library_name || lib.display_name || lib.canonical_name || '';
	var author = lib.author || '';
	var organization = lib.organization || '';
	var description = lib.description || '';
	var tags = (lib.tags || []).map(function(t) { return (t || '').toLowerCase().trim(); }).filter(Boolean);
	var fnNames = [];
	if (lib.public_functions && Array.isArray(lib.public_functions)) {
		lib.public_functions.forEach(function(fn) {
			var qn = fn.qualifiedName || fn.name || '';
			if (qn) fnNames = fnNames.concat(tokenize(qn));
		});
	}
	if (extraFnText) {
		fnNames = fnNames.concat(tokenize(extraFnText));
	}
	// System lib resource types feed into tags
	if (lib.resource_types && Array.isArray(lib.resource_types)) {
		lib.resource_types.forEach(function(rt) {
			var t = (rt || '').toLowerCase().trim();
			if (t && tags.indexOf(t) === -1) tags.push(t);
		});
	}

	var fields = {
		name:         tokenize(name),
		author:       tokenize(author),
		organization: tokenize(organization),
		description:  tokenize(description),
		tag:          tags.map(function(t) { return t.replace(/[^a-z0-9]/g, ''); }).filter(Boolean),
		'function':   fnNames
	};

	// De-duplicate each field's token list to avoid over-counting
	Object.keys(fields).forEach(function(f) {
		var seen = {};
		fields[f] = fields[f].filter(function(t) {
			if (seen[t]) return false;
			seen[t] = true;
			return true;
		});
	});

	// Build n-gram sets per token per field
	var ngramSets = {};
	Object.keys(fields).forEach(function(f) {
		ngramSets[f] = {};
		fields[f].forEach(function(token) {
			ngramSets[f][token] = ngrams(token, NGRAM_MIN, NGRAM_MAX);
		});
	});

	// Store forward doc
	this._docs[lib._id] = { type: type, fields: fields, ngramSets: ngramSets };

	// Build inverted index
	var self = this;
	Object.keys(fields).forEach(function(field) {
		fields[field].forEach(function(token) {
			if (!self._index[token]) self._index[token] = [];
			self._index[token].push({ id: lib._id, field: field });

			// N-gram inverted index (gram → tokens)
			var grams = ngramSets[field][token];
			grams.forEach(function(g) {
				if (!self._ngramIndex[g]) self._ngramIndex[g] = {};
				self._ngramIndex[g][token] = true;
			});
		});
	});
};

/**
 * Search the index.
 *
 * @param {string} textQuery        - Free-text search query
 * @param {object} [options]
 * @param {string[]} [options.tagFilters]    - Tags that must all match (AND logic)
 * @param {string[]} [options.authorFilters] - Authors where at least one must match (AND on each filter, OR across author/org fields)
 * @returns {Array<{id:string, score:number, type:string}>}  Sorted by descending score
 */
SearchIndex.prototype.search = function(textQuery, options) {
	options = options || {};
	var tagFilters = (options.tagFilters || []).map(function(t) { return (t || '').toLowerCase().trim().replace(/[^a-z0-9]/g, ''); }).filter(Boolean);
	var authorFilters = (options.authorFilters || []).map(function(a) { return (a || '').toLowerCase().trim(); }).filter(Boolean);
	var hasTagFilters = tagFilters.length > 0;
	var hasAuthorFilters = authorFilters.length > 0;

	var queryTokens = tokenize(textQuery || '');
	var hasTextQuery = queryTokens.length > 0;

	// If nothing to search, return empty
	if (!hasTagFilters && !hasAuthorFilters && !hasTextQuery) return [];

	var self = this;
	var scores = {}; // id → cumulative score

	// ---- Phase 1: Tag & Author filters (boolean gate) ----
	// Collect candidate IDs that pass tag + author filters
	var candidateIds = Object.keys(this._docs);

	if (hasTagFilters) {
		candidateIds = candidateIds.filter(function(id) {
			var doc = self._docs[id];
			var docTags = doc.fields.tag || [];
			return tagFilters.every(function(filterTag) {
				return docTags.some(function(t) { return t.indexOf(filterTag) !== -1; });
			});
		});
	}

	if (hasAuthorFilters) {
		candidateIds = candidateIds.filter(function(id) {
			var doc = self._docs[id];
			var authorTokens = (doc.fields.author || []);
			var orgTokens = (doc.fields.organization || []);
			// Reconstruct joined strings to match substring filters
			var authorStr = authorTokens.join(' ');
			var orgStr = orgTokens.join(' ');
			return authorFilters.every(function(filter) {
				return authorStr.indexOf(filter) !== -1 || orgStr.indexOf(filter) !== -1;
			});
		});
	}

	// If only tag/author filters, no text query — give all candidates score = 1
	if (!hasTextQuery) {
		return candidateIds.map(function(id) {
			return { id: id, score: 1, type: self._docs[id].type };
		});
	}

	// ---- Phase 2: Scored text search across candidates ----
	var candidateSet = {};
	candidateIds.forEach(function(id) { candidateSet[id] = true; });

	// Pre-compute n-grams for each query token
	var queryNgrams = {};
	queryTokens.forEach(function(qt) {
		queryNgrams[qt] = ngrams(qt, NGRAM_MIN, NGRAM_MAX);
	});

	// For each query token, find matching indexed tokens via:
	//   1) exact match
	//   2) prefix match (indexed token starts with query token)
	//   3) substring match (indexed token contains query token)
	//   4) fuzzy n-gram overlap above threshold

	queryTokens.forEach(function(qt) {
		var qtGrams = queryNgrams[qt];

		// Collect candidate indexed tokens via n-gram inverted index
		var relatedTokens = {};
		qtGrams.forEach(function(g) {
			var tokens = self._ngramIndex[g];
			if (tokens) {
				Object.keys(tokens).forEach(function(tok) {
					relatedTokens[tok] = true;
				});
			}
		});

		// For very short query tokens (1 char) that produce no n-grams,
		// fall back to a direct lookup in the inverted index
		if (qt.length < NGRAM_MIN && self._index[qt]) {
			relatedTokens[qt] = true;
		}

		// Score each related token
		Object.keys(relatedTokens).forEach(function(tok) {
			var quality;
			if (tok === qt) {
				quality = MATCH_QUALITY.exact;
			} else if (tok.indexOf(qt) === 0) {
				quality = MATCH_QUALITY.prefix;
			} else if (tok.indexOf(qt) !== -1) {
				quality = MATCH_QUALITY.substring;
			} else {
				// Fuzzy: compute n-gram overlap
				var tokGrams = ngrams(tok, NGRAM_MIN, NGRAM_MAX);
				var overlap = ngramOverlap(qtGrams, tokGrams);
				if (overlap < NGRAM_THRESHOLD) return; // below threshold
				quality = MATCH_QUALITY.ngram * overlap;
			}

			// Apply score to all postings of this token
			var postings = self._index[tok];
			if (!postings) return;
			postings.forEach(function(posting) {
				if (!candidateSet[posting.id]) return;
				var weight = FIELD_WEIGHTS[posting.field] || 1;
				if (!scores[posting.id]) scores[posting.id] = 0;
				scores[posting.id] += weight * quality;
			});
		});
	});

	// Bonus: if the full multi-word query appears as a contiguous substring
	// in the library name, give a large bonus (exact phrase match).
	var fullQuery = (textQuery || '').toLowerCase().trim();
	if (fullQuery.length > 1) {
		candidateIds.forEach(function(id) {
			var doc = self._docs[id];
			var nameStr = (doc.fields.name || []).join(' ');
			if (nameStr.indexOf(fullQuery) !== -1) {
				if (!scores[id]) scores[id] = 0;
				scores[id] += FIELD_WEIGHTS.name * MATCH_QUALITY.exact * 2;
			}
			// Also check description for full phrase
			var descStr = (doc.fields.description || []).join(' ');
			if (descStr.indexOf(fullQuery) !== -1) {
				if (!scores[id]) scores[id] = 0;
				scores[id] += FIELD_WEIGHTS.description * MATCH_QUALITY.exact;
			}
		});
	}

	// Build results array, filter to scored candidates only
	var results = [];
	Object.keys(scores).forEach(function(id) {
		if (scores[id] > 0) {
			results.push({ id: id, score: scores[id], type: self._docs[id].type });
		}
	});

	// Sort by descending score, then alphabetically by library name as tiebreaker
	results.sort(function(a, b) {
		if (b.score !== a.score) return b.score - a.score;
		var aName = (self._docs[a.id].fields.name || []).join(' ');
		var bName = (self._docs[b.id].fields.name || []).join(' ');
		return aName.localeCompare(bName);
	});

	return results;
};

/**
 * Get the number of indexed documents.
 */
SearchIndex.prototype.size = function() {
	return Object.keys(this._docs).length;
};

// ---- module export -----------------------------------------------------------
module.exports = SearchIndex;
