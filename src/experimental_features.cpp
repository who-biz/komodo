// Copyright (c) 2020-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "experimental_features.h"

#include "util/system.h"

bool fExperimentalLightWalletd = false;

std::optional<std::string> InitExperimentalMode()
{
    auto fExperimentalMode = GetBoolArg("-experimentalfeatures", false);
    fExperimentalLightWalletd  = GetBoolArg("-lightwalletd", false);

    // Fail if user has set experimental options without the global flag
    if (!fExperimentalMode) {
        if (fExperimentalLightWalletd) {
            return _("Light Walletd requires -experimentalfeatures.");
        }
    }
    return std::nullopt;
}

std::vector<std::string> GetExperimentalFeatures()
{
    std::vector<std::string> experimentalfeatures;
    if (fExperimentalLightWalletd)
        experimentalfeatures.push_back("lightwalletd");

    return experimentalfeatures;
}
