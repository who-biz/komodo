// Copyright (c) 2012-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "coins.h"

#include "memusage.h"
#include "random.h"
#include "version.h"
#include "policy/fees.h"
#include "komodo_defs.h"
#include "importcoin.h"
#include "pbaas/notarization.h"
#include "pbaas/reserves.h"

#include <assert.h>

/**
 * calculate number of bytes for the bitmask, and its number of non-zero bytes
 * each bit in the bitmask represents the availability of one output, but the
 * availabilities of the first two outputs are encoded separately
 */
void CCoins::CalcMaskSize(unsigned int &nBytes, unsigned int &nNonzeroBytes) const {
    unsigned int nLastUsedByte = 0;
    for (unsigned int b = 0; 2+b*8 < vout.size(); b++) {
        bool fZero = true;
        for (unsigned int i = 0; i < 8 && 2+b*8+i < vout.size(); i++) {
            if (!vout[2+b*8+i].IsNull()) {
                fZero = false;
                continue;
            }
        }
        if (!fZero) {
            nLastUsedByte = b + 1;
            nNonzeroBytes++;
        }
    }
    nBytes += nLastUsedByte;
}

bool CCoins::Spend(uint32_t nPos)
{
    if (nPos >= vout.size() || vout[nPos].IsNull())
        return false;
    vout[nPos].SetNull();
    Cleanup();
    return true;
}
bool CCoinsView::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const { return false; }
bool CCoinsView::GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const { return false; }
bool CCoinsView::GetNullifier(const uint256 &nullifier, ShieldedType type) const { return false; }
bool CCoinsView::GetCoins(const uint256 &txid, CCoins &coins) const { return false; }
bool CCoinsView::HaveCoins(const uint256 &txid) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
uint256 CCoinsView::GetBestAnchor(ShieldedType type) const { return uint256(); };
/*CCoinsViewBacked::GetHistoryLength(uint32_t epochId) const { return false; }
HistoryNode CCoinsViewBacked::GetHistoryAt(uint32_t epochId, HistoryIndex index) const { return false; }
uint256 CCoinsViewBacked::GetHistoryRoot(uint32_t epochId) const { return false; }
std::optional<libzcash::LatestSubtree> CCoinsViewBacked::GetLatestSubtree(ShieldedType type) const { return false; }
std::optional<libzcash::SubtreeData> CCoinsViewBacked::GetSubtreeData(ShieldedType type, libzcash::SubtreeIndex index) const { return false; }*/
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins,
                            const uint256 &hashBlock,
                            const uint256 &hashSproutAnchor,
                            const uint256 &hashSaplingAnchor,
                            CAnchorsSproutMap &mapSproutAnchors,
                            CAnchorsSaplingMap &mapSaplingAnchors,
                            CNullifiersMap &mapSproutNullifiers,
                            CNullifiersMap &mapSaplingNullifiers,
                            CHistoryCacheMap &historyCacheMap,
                            SubtreeCache &cacheSaplingSubtrees) { return false; }
bool CCoinsView::GetStats(CCoinsStats &stats) const { return false; }


CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }

bool CCoinsViewBacked::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const { return base->GetSproutAnchorAt(rt, tree); }
bool CCoinsViewBacked::GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const { return base->GetSaplingAnchorAt(rt, tree); }
bool CCoinsViewBacked::GetNullifier(const uint256 &nullifier, ShieldedType type) const { return base->GetNullifier(nullifier, type); }
bool CCoinsViewBacked::GetCoins(const uint256 &txid, CCoins &coins) const { return base->GetCoins(txid, coins); }
bool CCoinsViewBacked::HaveCoins(const uint256 &txid) const { return base->HaveCoins(txid); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
uint256 CCoinsViewBacked::GetBestAnchor(ShieldedType type) const { return base->GetBestAnchor(type); }
HistoryIndex CCoinsViewBacked::GetHistoryLength(uint32_t epochId) const { return base->GetHistoryLength(epochId); }
HistoryNode CCoinsViewBacked::GetHistoryAt(uint32_t epochId, HistoryIndex index) const { return base->GetHistoryAt(epochId, index); }
uint256 CCoinsViewBacked::GetHistoryRoot(uint32_t epochId) const { return base->GetHistoryRoot(epochId); }
std::optional<libzcash::LatestSubtree> CCoinsViewBacked::GetLatestSubtree(ShieldedType type) const { return base->GetLatestSubtree(type); }
std::optional<libzcash::SubtreeData> CCoinsViewBacked::GetSubtreeData(ShieldedType type, libzcash::SubtreeIndex index) const { return base->GetSubtreeData(type, index); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins,
                                  const uint256 &hashBlock,
                                  const uint256 &hashSproutAnchor,
                                  const uint256 &hashSaplingAnchor,
                                  CAnchorsSproutMap &mapSproutAnchors,
                                  CAnchorsSaplingMap &mapSaplingAnchors,
                                  CNullifiersMap &mapSproutNullifiers,
                                  CNullifiersMap &mapSaplingNullifiers,
                                  CHistoryCacheMap &historyCacheMap,
                                  SubtreeCache &cacheSaplingSubtrees) { 
    return base->BatchWrite(mapCoins, hashBlock,
                            hashSproutAnchor, hashSaplingAnchor, mapSproutAnchors,
                            mapSaplingAnchors, mapSproutNullifiers, mapSaplingNullifiers,
                            historyCacheMap, cacheSaplingSubtrees);
}
bool CCoinsViewBacked::GetStats(CCoinsStats &stats) const { return base->GetStats(stats); }

CCoinsKeyHasher::CCoinsKeyHasher() : salt(GetRandHash()) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), hasModifier(false), cachedCoinsUsage(0) { }

CCoinsViewCache::~CCoinsViewCache()
{
    assert(!hasModifier);
}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) +
           memusage::DynamicUsage(cacheSproutAnchors) +
           memusage::DynamicUsage(cacheSaplingAnchors) +
           memusage::DynamicUsage(cacheSproutNullifiers) +
           memusage::DynamicUsage(cacheSaplingNullifiers) +
           memusage::DynamicUsage(historyCacheMap) +
           memusage::DynamicUsage(cacheSaplingSubtrees) +
           cachedCoinsUsage;
}

CCoinsMap::const_iterator CCoinsViewCache::FetchCoins(const uint256 &txid) const {
    CCoinsMap::iterator it = cacheCoins.find(txid);
    if (it != cacheCoins.end())
        return it;
    CCoins tmp;
    if (!base->GetCoins(txid, tmp))
        return cacheCoins.end();
    CCoinsMap::iterator ret = cacheCoins.insert(std::make_pair(txid, CCoinsCacheEntry())).first;
    tmp.swap(ret->second.coins);
    if (ret->second.coins.IsPruned()) {
        // The parent only has an empty entry for this txid; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coins.DynamicMemoryUsage();
    return ret;
}


bool CCoinsViewCache::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const {
    CAnchorsSproutMap::const_iterator it = cacheSproutAnchors.find(rt);
    if (it != cacheSproutAnchors.end()) {
        if (it->second.entered) {
            tree = it->second.tree;
            return true;
        } else {
            return false;
        }
    }

    if (!base->GetSproutAnchorAt(rt, tree)) {
        return false;
    }

    CAnchorsSproutMap::iterator ret = cacheSproutAnchors.insert(std::make_pair(rt, CAnchorsSproutCacheEntry())).first;
    ret->second.entered = true;
    ret->second.tree = tree;
    cachedCoinsUsage += ret->second.tree.DynamicMemoryUsage();

    return true;
}

bool CCoinsViewCache::GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const {
    CAnchorsSaplingMap::const_iterator it = cacheSaplingAnchors.find(rt);
    if (it != cacheSaplingAnchors.end()) {
        if (it->second.entered) {
            tree = it->second.tree;
            return true;
        } else {
            return false;
        }
    }

    if (!base->GetSaplingAnchorAt(rt, tree)) {
        return false;
    }

    CAnchorsSaplingMap::iterator ret = cacheSaplingAnchors.insert(std::make_pair(rt, CAnchorsSaplingCacheEntry())).first;
    ret->second.entered = true;
    ret->second.tree = tree;
    cachedCoinsUsage += ret->second.tree.DynamicMemoryUsage();

    return true;
}

bool CCoinsViewCache::GetNullifier(const uint256 &nullifier, ShieldedType type) const {
    CNullifiersMap* cacheToUse;
    switch (type) {
        case SPROUT:
            cacheToUse = &cacheSproutNullifiers;
            break;
        case SAPLING:
            cacheToUse = &cacheSaplingNullifiers;
            break;
        default:
            throw std::runtime_error("Unknown shielded type");
    }
    CNullifiersMap::iterator it = cacheToUse->find(nullifier);
    if (it != cacheToUse->end())
        return it->second.entered;

    CNullifiersCacheEntry entry;
    bool tmp = base->GetNullifier(nullifier, type);
    entry.entered = tmp;

    cacheToUse->insert(std::make_pair(nullifier, entry));

    return tmp;
}

HistoryIndex CCoinsViewCache::GetHistoryLength(uint32_t epochId) const {
    HistoryCache& historyCache = SelectHistoryCache(epochId);
    return historyCache.length;
}

HistoryNode CCoinsViewCache::GetHistoryAt(uint32_t epochId, HistoryIndex index) const {
    HistoryCache& historyCache = SelectHistoryCache(epochId);

    if (index >= historyCache.length) {
        // Caller should ensure that it is limiting history
        // request to 0..GetHistoryLength(epochId)-1 range
        throw std::runtime_error("Invalid history request");
    }

    if (index >= historyCache.updateDepth) {
        return historyCache.appends[index];
    }

    return base->GetHistoryAt(epochId, index);
}

uint256 CCoinsViewCache::GetHistoryRoot(uint32_t epochId) const {
    return SelectHistoryCache(epochId).root;
}

std::optional<libzcash::LatestSubtree> CCoinsViewCache::GetLatestSubtree(ShieldedType type) const {
    switch (type) {
        case SAPLING:
            return cacheSaplingSubtrees.GetLatestSubtree(base);
        default:
            throw std::runtime_error("GetLatestSubtree: only sapling shielded type is supported");
    }
}

std::optional<libzcash::SubtreeData> CCoinsViewCache::GetSubtreeData(
    ShieldedType type,
    libzcash::SubtreeIndex index) const
{
    switch (type) {
        case SAPLING:
            return cacheSaplingSubtrees.GetSubtreeData(base, index);
        default:
            throw std::runtime_error("GetSubtreeData: unsupported shielded type");
    }
}

template<typename Tree, typename Cache, typename CacheIterator, typename CacheEntry>
void CCoinsViewCache::AbstractPushAnchor(
    const Tree &tree,
    ShieldedType type,
    Cache &cacheAnchors,
    uint256 &hash
)
{
    uint256 newrt = tree.root();

    auto currentRoot = GetBestAnchor(type);

    // We don't want to overwrite an anchor we already have.
    // This occurs when a block doesn't modify mapAnchors at all,
    // because there are no joinsplits. We could get around this a
    // different way (make all blocks modify mapAnchors somehow)
    // but this is simpler to reason about.
    if (currentRoot != newrt) {
        auto insertRet = cacheAnchors.insert(std::make_pair(newrt, CacheEntry()));
        CacheIterator ret = insertRet.first;

        ret->second.entered = true;
        ret->second.tree = tree;
        ret->second.flags = CacheEntry::DIRTY;

        if (insertRet.second) {
            // An insert took place
            cachedCoinsUsage += ret->second.tree.DynamicMemoryUsage();
        }

        hash = newrt;
    }
}

template<> void CCoinsViewCache::PushAnchor(const SproutMerkleTree &tree)
{
    AbstractPushAnchor<SproutMerkleTree, CAnchorsSproutMap, CAnchorsSproutMap::iterator, CAnchorsSproutCacheEntry>(
        tree,
        SPROUT,
        cacheSproutAnchors,
        hashSproutAnchor
    );
}

template<> void CCoinsViewCache::PushAnchor(const SaplingMerkleTree &tree)
{
    AbstractPushAnchor<SaplingMerkleTree, CAnchorsSaplingMap, CAnchorsSaplingMap::iterator, CAnchorsSaplingCacheEntry>(
        tree,
        SAPLING,
        cacheSaplingAnchors,
        hashSaplingAnchor
    );
}

template<>
void CCoinsViewCache::BringBestAnchorIntoCache(
    const uint256 &currentRoot,
    SproutMerkleTree &tree
)
{
    assert(GetSproutAnchorAt(currentRoot, tree));
}

template<>
void CCoinsViewCache::BringBestAnchorIntoCache(
    const uint256 &currentRoot,
    SaplingMerkleTree &tree
)
{
    assert(GetSaplingAnchorAt(currentRoot, tree));
}

void draftMMRNode(std::vector<uint32_t> &indices,
                  std::vector<HistoryEntry> &entries,
                  HistoryNode nodeData,
                  uint32_t alt,
                  uint32_t peak_pos)
{
    HistoryEntry newEntry = alt == 0
        ? libzcash::LeafToEntry(nodeData)
        // peak_pos - (1 << alt) is the array position of left child.
        // peak_pos - 1 is the array position of right child.
        : libzcash::NodeToEntry(nodeData, peak_pos - (1 << alt), peak_pos - 1);

    indices.push_back(peak_pos);
    entries.push_back(newEntry);
}

// Computes floor(log2(x)).
static inline uint32_t floor_log2(uint32_t x) {
    assert(x > 0);
    int log = 0;
    while (x >>= 1) { ++log; }
    return log;
}

// Computes the altitude of the largest subtree for an MMR with n nodes,
// which is floor(log2(n + 1)) - 1.
static inline uint32_t altitude(uint32_t n) {
    return floor_log2(n + 1) - 1;
}

uint32_t CCoinsViewCache::PreloadHistoryTree(uint32_t epochId, bool extra, std::vector<HistoryEntry> &entries, std::vector<uint32_t> &entry_indices) {
    auto treeLength = GetHistoryLength(epochId);

    if (treeLength <= 0) {
        throw std::runtime_error("Invalid PreloadHistoryTree state called - tree should exist");
    } else if (treeLength == 1) {
        entries.push_back(libzcash::LeafToEntry(GetHistoryAt(epochId, 0)));
        entry_indices.push_back(0);
        return 1;
    }

    uint32_t last_peak_pos = 0;
    uint32_t last_peak_alt = 0;
    uint32_t alt = 0;
    uint32_t peak_pos = 0;
    uint32_t total_peaks = 0;

    // Assume the following example peak layout with 14 leaves, and 25 stored nodes in
    // total (the "tree length"):
    //
    //             P
    //            /\
    //           /  \
    //          / \  \
    //        /    \  \  Altitude
    //     _A_      \  \    3
    //   _/   \_     B  \   2
    //  / \   / \   / \  C  1
    // /\ /\ /\ /\ /\ /\ /\ 0
    //
    // We start by determining the altitude of the highest peak (A).
    alt = altitude(treeLength);

    // We determine the position of the highest peak (A) by pretending it is the right
    // sibling in a tree, and its left-most leaf has position 0. Then the left sibling
    // of (A) has position -1, and so we can "jump" to the peak's position by computing
    // -1 + 2^(alt + 1) - 1.
    peak_pos = (1 << (alt + 1)) - 2;

    // Now that we have the position and altitude of the highest peak (A), we collect
    // the remaining peaks (B, C). We navigate the peaks as if they were nodes in this
    // Merkle tree (with additional imaginary nodes 1 and 2, that have positions beyond
    // the MMR's length):
    //
    //             / \
    //            /   \
    //           /     \
    //         /         \
    //       A ==========> 1
    //      / \          //  \
    //    _/   \_       B ==> 2
    //   /\     /\     /\    //
    //  /  \   /  \   /  \   C
    // /\  /\ /\  /\ /\  /\ /\
    //
    while (alt != 0) {
        // If peak_pos is out of bounds of the tree, we compute the position of its left
        // child, and drop down one level in the tree.
        if (peak_pos >= treeLength) {
            // left child, -2^alt
            peak_pos = peak_pos - (1 << alt);
            alt = alt - 1;
        }

        // If the peak exists, we take it and then continue with its right sibling.
        if (peak_pos < treeLength) {
            draftMMRNode(entry_indices, entries, GetHistoryAt(epochId, peak_pos), alt, peak_pos);

            last_peak_pos = peak_pos;
            last_peak_alt = alt;

            // right sibling
            peak_pos = peak_pos + (1 << (alt + 1)) - 1;
        }
    }

    total_peaks = entries.size();

    // Return early if we don't require extra nodes.
    if (!extra) return total_peaks;

    alt = last_peak_alt;
    peak_pos = last_peak_pos;


    //             P
    //            /\
    //           /  \
    //          / \  \
    //        /    \  \
    //     _A_      \  \
    //   _/   \_     B  \
    //  / \   / \   / \  C
    // /\ /\ /\ /\ /\ /\ /\
    //                   D E
    //
    // For extra peaks needed for deletion, we do extra pass on right slope of the last peak
    // and add those nodes + their siblings. Extra would be (D, E) for the picture above.
    while (alt > 0) {
        uint32_t left_pos = peak_pos - (1 << alt);
        uint32_t right_pos = peak_pos - 1;
        alt = alt - 1;

        // drafting left child
        draftMMRNode(entry_indices, entries, GetHistoryAt(epochId, left_pos), alt, left_pos);

        // drafting right child
        draftMMRNode(entry_indices, entries, GetHistoryAt(epochId, right_pos), alt, right_pos);

        // continuing on right slope
        peak_pos = right_pos;
    }

    return total_peaks;
}

HistoryCache& CCoinsViewCache::SelectHistoryCache(uint32_t epochId) const {
    auto entry = historyCacheMap.find(epochId);

    if (entry != historyCacheMap.end()) {
        return entry->second;
    } else {
        auto cache = HistoryCache(
            base->GetHistoryLength(epochId),
            base->GetHistoryRoot(epochId),
            epochId
        );
        return historyCacheMap.insert({epochId, cache}).first->second;
    }
}

void CCoinsViewCache::PushHistoryNode(uint32_t epochId, const HistoryNode node) {
    HistoryCache& historyCache = SelectHistoryCache(epochId);

    if (historyCache.length == 0) {
        // special case, it just goes into the cache right away
        historyCache.Extend(node);

        historyCache.root = uint256::FromRawBytes(mmr::hash_node(epochId, node));

        return;
    }

    std::vector<HistoryEntry> entries;
    std::vector<uint32_t> entry_indices;

    PreloadHistoryTree(epochId, false, entries, entry_indices);

    uint256 newRoot;
    std::array<HistoryNode, 32> appendBuf = {};

    auto effect = mmr::append(
        epochId,
        historyCache.length,
        {entry_indices.data(), entry_indices.size()},
        {entries.data(), entries.size()},
        node,
        {appendBuf.data(), 32}
    );

    for (size_t i = 0; i < effect.count; i++) {
        historyCache.Extend(appendBuf[i]);
    }

    historyCache.root = uint256::FromRawBytes(effect.root);
}

void CCoinsViewCache::PopHistoryNode(uint32_t epochId) {
    HistoryCache& historyCache = SelectHistoryCache(epochId);

    switch (historyCache.length) {
        case 0:
        {
            // Caller is generally not expected to pop from empty tree! Caller
            // should switch to previous epoch and pop history from there.

            // If we are doing an expected rollback that changes the consensus
            // branch ID for some upgrade (or introduces one that wasn't present
            // at the equivalent height) this will occur because
            // `SelectHistoryCache` selects the tree for the new consensus
            // branch ID, not the one that existed on the chain being rolled
            // back.

            // Sensible action is to truncate the history cache:
        }
        case 1:
        {
            // Just resetting tree to empty
            historyCache.Truncate(0);
            historyCache.root = uint256();
            return;
        }
        case 2:
        {
            // - A tree with one leaf has length 1.
            // - A tree with two leaves has length 3.
            throw std::runtime_error("a history tree cannot have two nodes");
        }
        case 3:
        {
            const HistoryNode tmpHistoryRoot = GetHistoryAt(epochId, 0);
            // After removing a leaf from a tree with two leaves, we are left
            // with a single-node tree, whose root is just the hash of that
            // node.
            auto newRoot = mmr::hash_node(
                epochId,
                tmpHistoryRoot);
            historyCache.Truncate(1);
            historyCache.root = uint256::FromRawBytes(newRoot);
            return;
        }
        default:
        {
            // This is a non-elementary pop, so use the full tree logic.
            std::vector<HistoryEntry> entries;
            std::vector<uint32_t> entry_indices;

            uint32_t peak_count = PreloadHistoryTree(epochId, true, entries, entry_indices);

            auto effect = mmr::remove(
                epochId,
                historyCache.length,
                {entry_indices.data(), entry_indices.size()},
                {entries.data(), entries.size()},
                peak_count
            );

            historyCache.Truncate(historyCache.length - effect.count);
            historyCache.root = uint256::FromRawBytes(effect.root);
            return;
        }
    }
}

void CCoinsViewCache::PushSubtree(ShieldedType type, libzcash::SubtreeData subtree)
{
    switch(type) {
        case SAPLING:
            return cacheSaplingSubtrees.PushSubtree(base, subtree);
        default:
            throw std::runtime_error("PushSubtree: only sapling shielded type is supported");
    }
}

void CCoinsViewCache::PopSubtree(ShieldedType type)
{
    switch(type) {
        case SAPLING:
            return cacheSaplingSubtrees.PopSubtree(base);
        default:
            throw std::runtime_error("PushSubtree: only sapling shielded type is supported");
    }
}

void CCoinsViewCache::ResetSubtrees(ShieldedType type)
{
    switch(type) {
        case SAPLING:
            return cacheSaplingSubtrees.ResetSubtrees();
        default:
            throw std::runtime_error("ResetSubtrees: unsupported shielded type");
    }
}

template<typename Tree, typename Cache, typename CacheEntry>
void CCoinsViewCache::AbstractPopAnchor(
    const uint256 &newrt,
    ShieldedType type,
    Cache &cacheAnchors,
    uint256 &hash
)
{
    auto currentRoot = GetBestAnchor(type);

    // Blocks might not change the commitment tree, in which
    // case restoring the "old" anchor during a reorg must
    // have no effect.
    if (currentRoot != newrt) {
        // Bring the current best anchor into our local cache
        // so that its tree exists in memory.
        {
            Tree tree;
            BringBestAnchorIntoCache(currentRoot, tree);
        }

        // Mark the anchor as unentered, removing it from view
        cacheAnchors[currentRoot].entered = false;

        // Mark the cache entry as dirty so it's propagated
        cacheAnchors[currentRoot].flags = CacheEntry::DIRTY;

        // Mark the new root as the best anchor
        hash = newrt;
    }
}

void CCoinsViewCache::PopAnchor(const uint256 &newrt, ShieldedType type) {
    switch (type) {
        case SPROUT:
            AbstractPopAnchor<SproutMerkleTree, CAnchorsSproutMap, CAnchorsSproutCacheEntry>(
                newrt,
                SPROUT,
                cacheSproutAnchors,
                hashSproutAnchor
            );
            break;
        case SAPLING:
            AbstractPopAnchor<SaplingMerkleTree, CAnchorsSaplingMap, CAnchorsSaplingCacheEntry>(
                newrt,
                SAPLING,
                cacheSaplingAnchors,
                hashSaplingAnchor
            );
            break;
        default:
            throw std::runtime_error("Unknown shielded type");
    }
}

void CCoinsViewCache::SetNullifiers(const CTransaction& tx, bool spent) {
    for (const JSDescription &joinsplit : tx.vJoinSplit) {
        for (const uint256 &nullifier : joinsplit.nullifiers) {
            std::pair<CNullifiersMap::iterator, bool> ret = cacheSproutNullifiers.insert(std::make_pair(nullifier, CNullifiersCacheEntry()));
            ret.first->second.entered = spent;
            ret.first->second.flags |= CNullifiersCacheEntry::DIRTY;
        }
    }
    for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
        std::pair<CNullifiersMap::iterator, bool> ret = cacheSaplingNullifiers.insert(std::make_pair(spendDescription.nullifier, CNullifiersCacheEntry()));
        ret.first->second.entered = spent;
        ret.first->second.flags |= CNullifiersCacheEntry::DIRTY;
    }
}

bool CCoinsViewCache::GetCoins(const uint256 &txid, CCoins &coins) const {
    CCoinsMap::const_iterator it = FetchCoins(txid);
    if (it != cacheCoins.end()) {
        coins = it->second.coins;
        return true;
    }
    return false;
}

CCoinsModifier CCoinsViewCache::ModifyCoins(const uint256 &txid) {
    assert(!hasModifier);
    std::pair<CCoinsMap::iterator, bool> ret = cacheCoins.insert(std::make_pair(txid, CCoinsCacheEntry()));
    size_t cachedCoinUsage = 0;
    if (ret.second) {
        if (!base->GetCoins(txid, ret.first->second.coins)) {
            // The parent view does not have this entry; mark it as fresh.
            ret.first->second.coins.Clear();
            ret.first->second.flags = CCoinsCacheEntry::FRESH;
        } else if (ret.first->second.coins.IsPruned()) {
            // The parent view only has a pruned entry for this; mark it as fresh.
            ret.first->second.flags = CCoinsCacheEntry::FRESH;
        }
    } else {
        cachedCoinUsage = ret.first->second.coins.DynamicMemoryUsage();
    }
    // Assume that whenever ModifyCoins is called, the entry will be modified.
    ret.first->second.flags |= CCoinsCacheEntry::DIRTY;
    return CCoinsModifier(*this, ret.first, cachedCoinUsage);
}

CCoinsModifier CCoinsViewCache::ModifyNewCoins(const uint256 &txid) {
    assert(!hasModifier);
    std::pair<CCoinsMap::iterator, bool> ret = cacheCoins.insert(std::make_pair(txid, CCoinsCacheEntry()));
    ret.first->second.coins.Clear();
    ret.first->second.flags = CCoinsCacheEntry::FRESH;
    ret.first->second.flags |= CCoinsCacheEntry::DIRTY;
    return CCoinsModifier(*this, ret.first, 0);
}

const CCoins* CCoinsViewCache::AccessCoins(const uint256 &txid) const {
    CCoinsMap::const_iterator it = FetchCoins(txid);
    if (it == cacheCoins.end()) {
        return NULL;
    } else {
        return &it->second.coins;
    }
}

bool CCoinsViewCache::HaveCoins(const uint256 &txid) const {
    CCoinsMap::const_iterator it = FetchCoins(txid);
    // We're using vtx.empty() instead of IsPruned here for performance reasons,
    // as we only care about the case where a transaction was replaced entirely
    // in a reorganization (which wipes vout entirely, as opposed to spending
    // which just cleans individual outputs).
    return (it != cacheCoins.end() && !it->second.coins.vout.empty());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
    {
        if (base)
        {
            hashBlock = base->GetBestBlock();
        }
        else
        {
            hashBlock = uint256();
        }
    }
    return hashBlock;
}


uint256 CCoinsViewCache::GetBestAnchor(ShieldedType type) const {
    switch (type) {
        case SPROUT:
            if (hashSproutAnchor.IsNull())
                hashSproutAnchor = base->GetBestAnchor(type);
            return hashSproutAnchor;
            break;
        case SAPLING:
            if (hashSaplingAnchor.IsNull())
                hashSaplingAnchor = base->GetBestAnchor(type);
            return hashSaplingAnchor;
            break;
        default:
            throw std::runtime_error("Unknown shielded type");
    }
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

void BatchWriteNullifiers(CNullifiersMap &mapNullifiers, CNullifiersMap &cacheNullifiers)
{
    for (CNullifiersMap::iterator child_it = mapNullifiers.begin(); child_it != mapNullifiers.end();) {
        if (child_it->second.flags & CNullifiersCacheEntry::DIRTY) { // Ignore non-dirty entries (optimization).
            CNullifiersMap::iterator parent_it = cacheNullifiers.find(child_it->first);

            if (parent_it == cacheNullifiers.end()) {
                CNullifiersCacheEntry& entry = cacheNullifiers[child_it->first];
                entry.entered = child_it->second.entered;
                entry.flags = CNullifiersCacheEntry::DIRTY;
            } else {
                if (parent_it->second.entered != child_it->second.entered) {
                    parent_it->second.entered = child_it->second.entered;
                    parent_it->second.flags |= CNullifiersCacheEntry::DIRTY;
                }
            }
        }
        CNullifiersMap::iterator itOld = child_it++;
        mapNullifiers.erase(itOld);
    }
}

template<typename Map, typename MapIterator, typename MapEntry>
void BatchWriteAnchors(
    Map &mapAnchors,
    Map &cacheAnchors,
    size_t &cachedCoinsUsage
)
{
    for (MapIterator child_it = mapAnchors.begin(); child_it != mapAnchors.end();)
    {
        if (child_it->second.flags & MapEntry::DIRTY) {
            MapIterator parent_it = cacheAnchors.find(child_it->first);

            if (parent_it == cacheAnchors.end()) {
                MapEntry& entry = cacheAnchors[child_it->first];
                entry.entered = child_it->second.entered;
                entry.tree = child_it->second.tree;
                entry.flags = MapEntry::DIRTY;

                cachedCoinsUsage += entry.tree.DynamicMemoryUsage();
            } else {
                if (parent_it->second.entered != child_it->second.entered) {
                    // The parent may have removed the entry.
                    parent_it->second.entered = child_it->second.entered;
                    parent_it->second.flags |= MapEntry::DIRTY;
                }
            }
        }

        MapIterator itOld = child_it++;
        mapAnchors.erase(itOld);
    }
}

void BatchWriteHistory(CHistoryCacheMap& historyCacheMap, CHistoryCacheMap& historyCacheMapIn) {
    for (auto nextHistoryCache = historyCacheMapIn.begin(); nextHistoryCache != historyCacheMapIn.end(); nextHistoryCache++) {
        auto historyCacheIn = nextHistoryCache->second;
        auto epochId = nextHistoryCache->first;

        auto historyCache = historyCacheMap.find(epochId);
        if (historyCache != historyCacheMap.end()) {
            // delete old entries since updateDepth
            historyCache->second.Truncate(historyCacheIn.updateDepth);

            // Replace/append new/updated entries. HistoryCache.Extend
            // auto-indexes the nodes, so we need to extend in the same order as
            // this cache is indexed.
            for (size_t i = historyCacheIn.updateDepth; i < historyCacheIn.length; i++) {
                historyCache->second.Extend(historyCacheIn.appends[i]);
            }

            // the lengths should now match
            assert(historyCache->second.length == historyCacheIn.length);

            // write current root
            historyCache->second.root = historyCacheIn.root;
        } else {
            // Just insert the history cache into its parent
            historyCacheMap.insert({epochId, historyCacheIn});
        }
    }
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins,
                                 const uint256 &hashBlockIn,
                                 const uint256 &hashSproutAnchorIn,
                                 const uint256 &hashSaplingAnchorIn,
                                 CAnchorsSproutMap &mapSproutAnchors,
                                 CAnchorsSaplingMap &mapSaplingAnchors,
                                 CNullifiersMap &mapSproutNullifiers,
                                 CNullifiersMap &mapSaplingNullifiers,
                                 CHistoryCacheMap &historyCacheMapIn,
                                 SubtreeCache &cacheSaplingSubtreesIn) {
    assert(!hasModifier);
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) { // Ignore non-dirty entries (optimization).
            CCoinsMap::iterator itUs = cacheCoins.find(it->first);
            if (itUs == cacheCoins.end()) {
                if (!it->second.coins.IsPruned()) {
                    // The parent cache does not have an entry, while the child
                    // cache does have (a non-pruned) one. Move the data up, and
                    // mark it as fresh (if the grandparent did have it, we
                    // would have pulled it in at first GetCoins).
                    assert(it->second.flags & CCoinsCacheEntry::FRESH);
                    CCoinsCacheEntry& entry = cacheCoins[it->first];
                    entry.coins.swap(it->second.coins);
                    cachedCoinsUsage += entry.coins.DynamicMemoryUsage();
                    entry.flags = CCoinsCacheEntry::DIRTY | CCoinsCacheEntry::FRESH;
                }
            } else {
                if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coins.IsPruned()) {
                    // The grandparent does not have an entry, and the child is
                    // modified and being pruned. This means we can just delete
                    // it from the parent.
                    cachedCoinsUsage -= itUs->second.coins.DynamicMemoryUsage();
                    cacheCoins.erase(itUs);
                } else {
                    // A normal modification.
                    cachedCoinsUsage -= itUs->second.coins.DynamicMemoryUsage();
                    itUs->second.coins.swap(it->second.coins);
                    cachedCoinsUsage += itUs->second.coins.DynamicMemoryUsage();
                    itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                }
            }
        }
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }

    ::BatchWriteAnchors<CAnchorsSproutMap, CAnchorsSproutMap::iterator, CAnchorsSproutCacheEntry>(mapSproutAnchors, cacheSproutAnchors, cachedCoinsUsage);
    ::BatchWriteAnchors<CAnchorsSaplingMap, CAnchorsSaplingMap::iterator, CAnchorsSaplingCacheEntry>(mapSaplingAnchors, cacheSaplingAnchors, cachedCoinsUsage);

    ::BatchWriteNullifiers(mapSproutNullifiers, cacheSproutNullifiers);
    ::BatchWriteNullifiers(mapSaplingNullifiers, cacheSaplingNullifiers);

    ::BatchWriteHistory(historyCacheMap, historyCacheMapIn);

    cacheSaplingSubtrees.BatchWrite(base, cacheSaplingSubtreesIn);

    hashSproutAnchor = hashSproutAnchorIn;
    hashSaplingAnchor = hashSaplingAnchorIn;
    hashBlock = hashBlockIn;
    return true;
}

bool CCoinsViewCache::Flush() {

    cacheSaplingSubtrees.Initialize(base);
    bool fOk = base->BatchWrite(cacheCoins,

    bool fOk = base->BatchWrite(cacheCoins,
                                hashBlock,
                                hashSproutAnchor,
                                hashSaplingAnchor,
                                cacheSproutAnchors,
                                cacheSaplingAnchors,
                                cacheSproutNullifiers,
                                cacheSaplingNullifiers,
                                historyCacheMap,
                                cacheSaplingSubtrees);
    cacheCoins.clear();
    cacheSproutAnchors.clear();
    cacheSaplingAnchors.clear();
    cacheSproutNullifiers.clear();
    cacheSaplingNullifiers.clear();
    historyCacheMap.clear();
    cacheSaplingSubtrees.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

const CTxOut &CCoinsViewCache::GetOutputFor(const CTxIn& input) const
{
    const CCoins* coins = AccessCoins(input.prevout.hash);
    assert(coins && coins->IsAvailable(input.prevout.n));
    return coins->vout[input.prevout.n];
}

//uint64_t komodo_interest(int32_t txheight,uint64_t nValue,uint32_t nLockTime,uint32_t tiptime);
uint64_t komodo_accrued_interest(int32_t *txheightp,uint32_t *locktimep,uint256 hash,int32_t n,int32_t checkheight,uint64_t checkvalue,int32_t tipheight);
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];

const CScript &CCoinsViewCache::GetSpendFor(const CCoins *coins, const CTxIn& input)
{
    assert(coins);
    if (coins->nHeight < 6400 && !strcmp(ASSETCHAINS_SYMBOL, "VRSC"))
    {
        std::string hc = input.prevout.hash.ToString();
        if (LaunchMap().lmap.count(hc))
        {
            CTransactionExceptionData &txData = LaunchMap().lmap[hc];
            if ((txData.voutMask & (((uint64_t)1) << (uint64_t)input.prevout.n)) != 0)
            {
                return txData.scriptPubKey;
            }
        }
    }
    return coins->vout[input.prevout.n].scriptPubKey;
}

const CScript &CCoinsViewCache::GetSpendFor(const CTxIn& input) const
{
    const CCoins* coins = AccessCoins(input.prevout.hash);
    return GetSpendFor(coins, input);
}

CAmount CCoinsViewCache::GetValueIn(int32_t nHeight, int64_t *interestp, const CTransaction& tx, uint32_t tiptime) const
{
    CAmount value,nResult = 0;
    if ( interestp != 0 )
        *interestp = 0;
    if ( tx.IsCoinImport() )
        return GetCoinImportValue(tx);
    if ( tx.IsCoinBase() != 0 )
        return 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        value = 0;
        const CCoins* coins = AccessCoins(tx.vin[i].prevout.hash);
        if (coins && coins->IsAvailable(tx.vin[i].prevout.n))
        {
            // if we are a PBaaS chain tx with a coinbase currency state input, all non-shielded inputs are effectively considered burned, since this must be the
            // block's conversion transaction and they are assumed to all be converted
            COptCCParams p;
            if (!_IsVerusActive() && coins->fCoinBase && coins->vout[tx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_CURRENCYSTATE)
            {
                CCoinbaseCurrencyState cbcs;
                if (p.vData.size() && (cbcs = CCoinbaseCurrencyState(p.vData[0])).IsValid() && cbcs.IsFractional())
                {
                    nResult = coins->vout[tx.vin[i].prevout.n].nValue;
                    break;
                }
            }
            else
            {
                value = coins->vout[tx.vin[i].prevout.n].nValue;
            }
        }
        else
        {
            printf("%s: input #%d txid:n (%s:%u) not available in view. returning 0\n", __func__, i, tx.vin[i].prevout.hash.GetHex().c_str(), tx.vin[i].prevout.n);
            return 0;
        }

        nResult += value;
#ifdef KOMODO_ENABLE_INTEREST
        if ( ASSETCHAINS_SYMBOL[0] == 0 && nHeight >= 60000 )
        {
            if ( value >= 10*COIN )
            {
                int64_t interest; int32_t txheight; uint32_t locktime;
                interest = komodo_accrued_interest(&txheight,&locktime,tx.vin[i].prevout.hash,tx.vin[i].prevout.n,0,value,(int32_t)nHeight);
                //printf("nResult %.8f += val %.8f interest %.8f ht.%d lock.%u tip.%u\n",(double)nResult/COIN,(double)value/COIN,(double)interest/COIN,txheight,locktime,tiptime);
                //fprintf(stderr,"nResult %.8f += val %.8f interest %.8f ht.%d lock.%u tip.%u\n",(double)nResult/COIN,(double)value/COIN,(double)interest/COIN,txheight,locktime,tiptime);
                nResult += interest;
                if (interestp)
                    (*interestp) += interest;
            }
        }
#endif
    }
    nResult += tx.GetShieldedValueIn();

    return nResult;
}

CCurrencyValueMap CCoinsViewCache::GetReserveValueIn(int32_t nHeight, const CTransaction& tx) const
{
    CCurrencyValueMap retMap;

    CAmount nResult = 0;

    // coinbases have no inputs
    if ( tx.IsCoinBase() != 0 )
        return retMap;

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const CCoins* coins = AccessCoins(tx.vin[i].prevout.hash);
        if (coins && coins->IsAvailable(tx.vin[i].prevout.n))
        {
            retMap += coins->vout[tx.vin[i].prevout.n].scriptPubKey.ReserveOutValue();
        }
        else
        {
            // if coins aren't available, fail all
            return CCurrencyValueMap();
        }
    }
    return retMap;
}

//bool CCoinsViewCache::HaveJoinSplitRequirements(const CTransaction& tx) const
bool CCoinsViewCache::HaveShieldedRequirements(const CTransaction& tx) const
{
    boost::unordered_map<uint256, SproutMerkleTree, CCoinsKeyHasher> intermediates;

    BOOST_FOREACH(const JSDescription &joinsplit, tx.vJoinSplit)
    {
        BOOST_FOREACH(const uint256& nullifier, joinsplit.nullifiers)
        {
            if (GetNullifier(nullifier, SPROUT)) {
                // If the nullifier is set, this transaction
                // double-spends!
                return false;
            }
        }

        SproutMerkleTree tree;
        auto it = intermediates.find(joinsplit.anchor);
        if (it != intermediates.end()) {
            tree = it->second;
        } else if (!GetSproutAnchorAt(joinsplit.anchor, tree)) {
            return false;
        }

        BOOST_FOREACH(const uint256& commitment, joinsplit.commitments)
        {
            tree.append(commitment);
        }

        intermediates.insert(std::make_pair(tree.root(), tree));
    }

    for (const SpendDescription &spendDescription : tx.vShieldedSpend) {
        if (GetNullifier(spendDescription.nullifier, SAPLING)) // Prevent double spends
            return false;

        SaplingMerkleTree tree;
        if (!GetSaplingAnchorAt(spendDescription.anchor, tree)) {
            return false;
        }
    }

    return true;
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsMint()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            const COutPoint &prevout = tx.vin[i].prevout;
            const CCoins* coins = AccessCoins(prevout.hash);
            if (!coins || !coins->IsAvailable(prevout.n)) {
                //fprintf(stderr,"HaveInputs missing input %s/v%d\n",prevout.hash.ToString().c_str(),prevout.n);
                return false;
            }
        }
    }
    return true;
}

double CCoinsViewCache::GetPriority(const CTransaction &tx, int nHeight, const CReserveTransactionDescriptor *desc, const CCurrencyState *currencyState) const
{
    if (tx.IsCoinBase())
        return 0.0;

    // Shielded transfers do not reveal any information about the value or age of a note, so we
    // cannot apply the priority algorithm used for transparent utxos.  Instead, we just
    // use the maximum priority for all (partially or fully) shielded transactions.
    // (Note that coinbase transactions cannot contain JoinSplits, or Sapling shielded Spends or Outputs.)

    if (tx.vJoinSplit.size() > 0 || tx.vShieldedSpend.size() > 0 || tx.vShieldedOutput.size() > 0 || tx.IsCoinImport()) {
        return MAX_PRIORITY;
    }

    // FIXME: this logic is partially duplicated between here and CreateNewBlock in miner.cpp.
    double dResult = 0.0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        const CCoins* coins = AccessCoins(txin.prevout.hash);
        assert(coins);
        if (!coins->IsAvailable(txin.prevout.n)) continue;
        if (coins->nHeight < nHeight) {
            if (currencyState && desc)
            {
                dResult += (coins->vout[txin.prevout.n].nValue + currencyState->NativeToReserve(currencyState->ReserveToNative(coins->vout[txin.prevout.n].ReserveOutValue()), currencyState->GetReserveMap()[ASSETCHAINS_CHAINID])) *
                           (nHeight-coins->nHeight);
            }
            else
            {
                dResult += coins->vout[txin.prevout.n].nValue * (nHeight-coins->nHeight);
            }
        }
    }
    return tx.ComputePriority(dResult);
}

CCoinsModifier::CCoinsModifier(CCoinsViewCache& cache_, CCoinsMap::iterator it_, size_t usage) : cache(cache_), it(it_), cachedCoinUsage(usage) {
    assert(!cache.hasModifier);
    cache.hasModifier = true;
}

CCoinsModifier::~CCoinsModifier()
{
    assert(cache.hasModifier);
    cache.hasModifier = false;
    it->second.coins.Cleanup();
    cache.cachedCoinsUsage -= cachedCoinUsage; // Subtract the old usage
    if ((it->second.flags & CCoinsCacheEntry::FRESH) && it->second.coins.IsPruned()) {
        cache.cacheCoins.erase(it);
    } else {
        // If the coin still exists after the modification, add the new usage
        cache.cachedCoinsUsage += it->second.coins.DynamicMemoryUsage();
    }
}

void SubtreeCache::clear() {
    initialized = false;
    parentLatestSubtree = std::nullopt;
    newSubtrees.clear();
}

void SubtreeCache::Initialize(CCoinsView *parentView)
{
    if (!initialized) {
        parentLatestSubtree = parentView->GetLatestSubtree(type);
        initialized = true;
    }
}

std::optional<libzcash::LatestSubtree> SubtreeCache::GetLatestSubtree(CCoinsView *parentView) {
    Initialize(parentView);

    if (newSubtrees.size() > 0) {
        // The latest subtree is in our cache.

        libzcash::SubtreeIndex index;
        if (parentLatestSubtree.has_value()) {
            // The best subtree index is newSubtrees.size() larger than
            // our parent view's subtree index.
            index = parentLatestSubtree.value().index + newSubtrees.size();
        } else {
            // The parent view has no subtrees
            index = newSubtrees.size() - 1;
        }

        auto lastSubtree = newSubtrees.back();
        return libzcash::LatestSubtree(index, lastSubtree.root, lastSubtree.nHeight);
    } else {
        return parentLatestSubtree;
    }
}

std::optional<libzcash::SubtreeData> SubtreeCache::GetSubtreeData(CCoinsView *parentView, libzcash::SubtreeIndex index) {
    Initialize(parentView);

    auto latestSubtree = GetLatestSubtree(parentView);

    if (!latestSubtree.has_value() || latestSubtree.value().index < index) {
        // This subtree isn't complete in our local view
        return std::nullopt;
    }

    if (parentLatestSubtree.has_value()) {
        if (index <= parentLatestSubtree.value().index) {
            // This subtree in question must have previously been flushed to the parent cache layer,
            // so we ask for it there.
            return parentView->GetSubtreeData(type, index);
        } else {
            // Get the index into our local `newSubtrees` where the subtree should
            // be located.
            auto localIndex = index - (parentLatestSubtree.value().index + 1);
            assert(newSubtrees.size() > localIndex);
            return newSubtrees[localIndex];
        }
    } else {
        // The index we've been given is the index into our local `newSubtrees`
        // since the parent view has no subtrees.
        assert(newSubtrees.size() > index);
        return newSubtrees[index];
    }
}

void SubtreeCache::PushSubtree(CCoinsView *parentView, libzcash::SubtreeData subtree) {
    Initialize(parentView);

    newSubtrees.push_back(subtree);
}

void SubtreeCache::PopSubtree(CCoinsView *parentView) {
    Initialize(parentView);

    if (newSubtrees.empty()) {
        // Try to pop from the parent view
        if (parentLatestSubtree.has_value()) {
            libzcash::SubtreeIndex parentIndex = parentLatestSubtree.value().index;

            if (parentIndex == 0) {
                // This pops the only subtree left in the parent view.
                parentLatestSubtree = std::nullopt;
            } else {
                parentIndex -= 1;
                auto newParent = parentView->GetSubtreeData(type, parentIndex);
                if (!newParent.has_value()) {
                    throw std::runtime_error("cache inconsistency; parent view does not have subtree");
                }

                parentLatestSubtree = libzcash::LatestSubtree(
                    parentIndex,
                    newParent.value().root,
                    newParent.value().nHeight
                );
            }
        } else {
            throw std::runtime_error("tried to pop a subtree from an empty subtree list");
        }
    } else {
        newSubtrees.pop_back();
    }
}

void SubtreeCache::ResetSubtrees() {
    // This ensures that all subtrees will be popped from the parent view
    initialized = true;

    parentLatestSubtree = std::nullopt;
    newSubtrees.clear();
}

void SubtreeCache::BatchWrite(CCoinsView *parentView, SubtreeCache &childMap) {
    Initialize(parentView);
    auto bestSubtree = GetLatestSubtree(parentView);
    if (!bestSubtree.has_value()) {
        // We do not have any local subtrees, so it cannot be possible
        // for the childMap to think we have any latest subtree, which
        // suggests the wrong childMap was passed or the wrong backing
        // view has been set in the cache.
        if (childMap.parentLatestSubtree.has_value()) {
            throw std::runtime_error("cache inconsistency; child view of parent's latest subtree cannot be correct");
        }
    } else {
        uint64_t pops;
        // Compute the number of times we must PopSubtree until our best subtree
        // is the same as the child's parentLatestSubtree index.
        if (childMap.parentLatestSubtree.has_value()) {
            if (childMap.parentLatestSubtree.value().index > bestSubtree.value().index) {
                throw std::runtime_error("cache inconsistency; child view of parent's latest subtree cannot be correct");
            }
            pops = bestSubtree.value().index - childMap.parentLatestSubtree.value().index;
        } else {
            // We have to pop everything.
            pops = bestSubtree.value().index + 1;
        }

        for (uint64_t i = 0; i < pops; i++) {
            PopSubtree(parentView);
        }
    }

    // Now we can inherit the child's new subtrees
    newSubtrees.insert(
        newSubtrees.end(),
        std::make_move_iterator(childMap.newSubtrees.begin()),
        std::make_move_iterator(childMap.newSubtrees.end())
    );

    childMap.clear();
}
