// Resolve a stored avatar path to a servable URL (used by MessageList +
// ConversationList). Local 'avatars/…' paths are served under /api/media/;
// full http(s) URLs pass through; anything else has no avatar (initial-letter fallback).
export function resolveAvatarUrl(url) {
  if (!url) return null
  if (url.startsWith('avatars/')) return `/api/media/${url}`
  if (url.startsWith('http')) return url
  return null
}

// Resolve a local media path (images, voice, video, emoji) to protected URL.
export function resolveMediaUrl(path) {
  if (!path) return null
  if (path.startsWith('/api/media/')) return path
  if (path.startsWith('/media/')) return path.replace('/media/', '/api/media/')
  // Relative paths under media/
  return `/api/media/${path}`
}
