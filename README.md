Playing around with Google's gopacket package.

testWifiMonitorPcap(...) can be used to take a monitor mode packet capture on MacOS. It automatically goes through all the 2.4GHz channels and saves frames on a .pcap file. Run with --nopcap flag to only see statistics about frames seen on different channels, example:

Current channel: 5
Total Frames Seen: 68992

```
Channel 1	frames: 16189	mon for 40.014687502s
Channel 2	frames: 3814	mon for 40.009432728s
Channel 3	frames: 2346	mon for 40.024715095s
Channel 4	frames: 2333	mon for 40.023917644s
Channel 5	frames: 2549	mon for 35.011436319s
Channel 6	frames: 6762	mon for 35.014880666s
Channel 7	frames: 2191	mon for 35.026237061s
Channel 8	frames: 1288	mon for 35.016483849s
Channel 9	frames: 2522	mon for 35.01431395s
Channel 10	frames: 4962	mon for 35.015464523s
Channel 11	frames: 17802	mon for 35.019319409s
Channel 12	frames: 5012	mon for 35.019061602s
Channel 13	frames: 1222	mon for 35.017535449s
```

Note: Apparently on MacOS packetSource.Packets() seem to take over 100% of a CPU core.
