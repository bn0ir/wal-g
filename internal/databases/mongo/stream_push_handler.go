package mongo

import (
	"io"
	"os"

	"github.com/wal-g/wal-g/internal"

	"github.com/wal-g/wal-g/internal/tracelog"
	"github.com/wal-g/wal-g/utility"
)

func HandleStreamPush(uploader *Uploader) {
	if !internal.FileIsPiped(os.Stdin) {
		tracelog.ErrorLogger.Fatal("Use stdin\n")
	}
	uploader.UploadingFolder = uploader.UploadingFolder.GetSubFolder(utility.BaseBackupPath)
	err := uploader.UploadStream(os.Stdin)
	if err != nil {
		tracelog.ErrorLogger.Fatalf("%+v\n", err)
	}
}

// TODO : unit tests
// UploadStream compresses a stream and uploads it.
func (uploader *Uploader) UploadStream(stream io.Reader) error {
	timeStart := utility.TimeNowCrossPlatformLocal()
	backupName, err := uploader.PushStream(stream)
	internal.UploadSentinel(uploader.Uploader, &StreamSentinelDto{StartLocalTime: timeStart}, backupName)

	return err
}
