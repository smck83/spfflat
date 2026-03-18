docker build -t ghcr.io/smck83/spfflat . --no-cache

docker run -it `
  -e SOURCE_ID=abcd123 `
  -e MY_DOMAINS="zen.spf.guru" `
  -e DNS_PROVIDER=bunny `
  -e BUNNY_API_KEY=64ec0ffa-c31a-4924-a7a5-532e9bc450289bbc324a-1b51-43f2-a7b4-f735a419d60a `
  -e SCHEDULE=2 `
  ghcr.io/smck83/spfflat