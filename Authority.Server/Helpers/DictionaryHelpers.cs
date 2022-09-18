using System.Collections.Generic;

namespace Authority.Server.Helpers
{
    public static class DictionaryHelpers
    {
        public static TValue TryGetValue<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue def = default) => 
            dictionary.TryGetValue(key, out var value) ? value : def;
    }
}