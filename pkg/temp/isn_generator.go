package temp

import "time"

var curISN uint32

/*
* Instead of Generating the initial sequence number (ISN) randomly, we do it by means of
* ISN generator that increments a counter by 1 roughly every 4 microseconds
* -This corresponds to the "clock" in RFC9293
* -One cycle takes around 4.55 hours, which is longer than the Maxmimum Segement Lifetime
 */

func GetISN() uint32 {
	return curISN
}

func ISNGenerator() {
	curISN = 0
	micr, _ := time.ParseDuration("4ms")
	for {
		time.Sleep(micr)
		curISN += 1
	}
}
