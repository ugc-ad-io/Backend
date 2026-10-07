from pathlib import Path
root = Path(r'C:\Users\meetr\Desktop\ugcapp')
p = root / 'src/screens/BrandCreators.tsx'
s = p.read_text(encoding='utf-8')
a = s.index('  // Small picture + clip from the media bucket;')
b = s.index('\n  return (', a)
s = s[:a] + '''  // Prefer the small preview, but uploads are playable even before a preview exists.
  const small = video ? previewOf(media) : null;
  const [smallFailed, setSmallFailed] = useState(false);
  const [clipFailed, setClipFailed] = useState(false);
  const [videoFailed, setVideoFailed] = useState(false);
  const [ready, setReady] = useState(false);
  const useSmall = !!small && !clipFailed;
  const playbackUrl = useSmall ? small!.clip : media;
  const poster = small && !smallFailed ? small.poster : videoPoster(media) || avatar;
  const showClip = video && play && !videoFailed;

  useEffect(() => {
    setSmallFailed(false);
    setClipFailed(false);
    setVideoFailed(false);
    setReady(false);
  }, [media]);
  useEffect(() => { setReady(false); }, [showClip, playbackUrl]);
''' + s[b:]
s = s.replace('source={{ uri: small!.clip }}', 'key={playbackUrl}\n            source={{ uri: playbackUrl! }}')
s = s.replace('onError={() => setClipFailed(true)}', 'onError={() => useSmall ? setClipFailed(true) : setVideoFailed(true)}')
p.write_text(s, encoding='utf-8')
p = root / 'src/screens/CreatorPublicProfile.tsx'
s = p.read_text(encoding='utf-8')
s = s.replace('  const poster = videoPoster(item.url);', '  const poster = videoPoster(item.url);\n  const [posterFailed, setPosterFailed] = useState(false);')
s = s.replace('onPress={() => isVideo(item.url) && poster && setPlaying(p => !p)}', 'onPress={() => isVideo(item.url) && setPlaying(p => !p)}\n        accessibilityRole="button"\n        accessibilityLabel={playing ? "Pause portfolio video" : "Play portfolio video"}')
s = s.replace(') : isVideo(item.url) && poster ? (', ') : isVideo(item.url) ? (')
s = s.replace('<Image source={{ uri: poster }} style={styles.videoMedia} />', '''{poster && !posterFailed ? (
              <Image source={{ uri: poster }} style={styles.videoMedia} onError={() => setPosterFailed(true)} />
            ) : (
              <View style={[styles.videoMedia, styles.videoMissing]}>
                <Icon name="camera" color="#B9BDD4" size={22} />
                <Text style={styles.videoMissingText}>Tap to play video</Text>
              </View>
            )}''')
p.write_text(s, encoding='utf-8')
p = root / '__tests__/BrandCreators.playback.test.tsx'
s = p.read_text(encoding='utf-8') + '''
test('missing preview clips fall back to the actual uploaded videos', async () => {
  await open();
  showRows();
  expect(players()).toHaveLength(4);
  act(() => { players().forEach(player => player.props.onError()); });
  expect(players()).toHaveLength(4);
  expect(players().every(player => player.props.source.uri.includes('/video/upload/v1/'))).toBe(true);
  expect(players().every(player => !player.props.source.uri.includes('/previews/'))).toBe(true);
});
test('a video from a host without generated previews still plays', async () => {
  (globalThis as any).fetch = jest.fn(async () => ({ ok: true, status: 200,
    json: async () => [{ id: 'upload-1', name: 'New creator', portfolio_preview: 'https://cdn.example.com/upload.mp4', profile_photo: 'https://cdn.example.com/avatar.jpg' }],
  }));
  await open();
  showRows([0]);
  expect(players()).toHaveLength(1);
  expect(players()[0].props.source.uri).toBe('https://cdn.example.com/upload.mp4');
});
'''
p.write_text(s,encoding='utf-8')
