/**
 * Model discovery & ranking.
 *
 * The user did not pick a preferred model, so when LLM_MODEL is unset we rank
 * whatever the provider offers and choose a sensible default: code-capable
 * chat models first, then general chat models, then everything else.
 *
 * This module is pure (no network) so it is easy to unit test.
 */

// Substrings that suggest a strong instruction/code-following model.
const CODE_HINTS = ['coder', 'code', 'deepseek', 'qwen', 'codellama', 'starcoder', 'granite'];
const CHAT_HINTS = ['llama', 'mistral', 'mixtral', 'gemma', 'phi', 'command', 'yi', 'glm', 'nemotron'];
const EMBED_HINTS = ['embed', 'embedding', 'bge', 'nomic-embed', 'all-minilm'];

// Models known to be tiny and poor at agentic reasoning; deprioritize.
const TINY_HINTS = [':1b', ':1.5b', ':2b', '0.5b', 'smollm'];

function scoreModel(name) {
    const lower = String(name).toLowerCase();
    let score = 0;

    if (EMBED_HINTS.some((h) => lower.includes(h))) score -= 100;
    if (CODE_HINTS.some((h) => lower.includes(h))) score += 50;
    if (CHAT_HINTS.some((h) => lower.includes(h))) score += 20;
    if (TINY_HINTS.some((h) => lower.includes(h))) score -= 15;

    // Mild preference for instruction-tuned / chat variants.
    if (/(instruct|chat)/.test(lower)) score += 5;

    return score;
}

/**
 * Rank a list of model names, best first.
 * @param {string[]} models
 * @returns {string[]}
 */
function rankModels(models) {
    return [...models].sort((a, b) => {
        const diff = scoreModel(b) - scoreModel(a);
        if (diff !== 0) return diff;
        return a.localeCompare(b);
    });
}

/**
 * Pick the best available model.
 * @param {string[]} models
 * @returns {string|null}
 */
function pickModel(models) {
    if (!Array.isArray(models) || models.length === 0) return null;
    return rankModels(models)[0];
}

module.exports = { scoreModel, rankModels, pickModel, CODE_HINTS, CHAT_HINTS };
