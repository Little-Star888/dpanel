package docker

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	imagecopy "github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker/daemon"
	"github.com/containers/image/v5/oci/archive"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/donknap/dpanel/common/function"
	"github.com/donknap/dpanel/common/types/fs"
	"github.com/mcuadros/go-version"
)

func (self Client) ImageInspectFileList(ctx context.Context, imageID string) (pathInfo []*fs.FileData, path []string, err error) {
	imageInfo, err := self.Client.ImageInspect(ctx, imageID)
	if err != nil {
		return nil, nil, err
	}
	dockerVersion, _ := self.Client.ServerVersion(ctx)
	// 如果当前 docker 版本大于 25 则获取 rootfs 否则直接查找 tar 的文件
	layers := function.PluckArrayWalk(imageInfo.RootFS.Layers, func(i string) (string, bool) {
		if _, after, ok := strings.Cut(i, "sha256:"); ok {
			return fmt.Sprintf("blobs/sha256/%s", after), true
		}
		return "", false
	})
	out, err := self.Client.ImageSave(ctx, []string{
		imageID,
	})

	tarReader := tar.NewReader(out)
	for {
		header, err := tarReader.Next()
		if err != nil {
			break
		}
		var tarFileList []*fs.FileData
		if version.Compare(dockerVersion.Version, "25", ">=") && function.InArray(layers, header.Name) {
			tarFileList, err = getFileListFromTar(tar.NewReader(tarReader))
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		} else if strings.HasSuffix(header.Name, ".tar") {
			tarFileList, err = getFileListFromTar(tar.NewReader(tarReader))
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		} else if strings.HasSuffix(header.Name, ".tar.gz") || strings.HasSuffix(header.Name, "tgz") {
			gzReader, err := gzip.NewReader(tarReader)
			if err != nil {
				return nil, nil, err
			}
			tarFileList, err = getFileListFromTar(tar.NewReader(gzReader))
			_ = gzReader.Close()
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		}
		pathInfo = append(pathInfo, tarFileList...)
	}
	sort.Slice(pathInfo, func(i, j int) bool {
		return pathInfo[i].IsDir && !pathInfo[j].IsDir
	})
	sort.Slice(pathInfo, func(i, j int) bool {
		if pathInfo[i].IsDir != pathInfo[j].IsDir {
			return pathInfo[i].IsDir
		}
		return pathInfo[i].Name < pathInfo[j].Name
	})

	path = make([]string, 0)
	pathInfo = function.PluckArrayWalk(pathInfo, func(i *fs.FileData) (*fs.FileData, bool) {
		if function.InArray(path, i.Name) {
			return nil, false
		} else {
			path = append(path, i.Name)
			return i, true
		}
	})
	return pathInfo, path, nil
}

func getFileListFromTar(tarReader *tar.Reader) (files []*fs.FileData, err error) {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// always ensure relative path notations are not parsed as part of the filename
		name := path.Clean(header.Name)
		if name == "." {
			continue
		}

		switch header.Typeflag {
		case tar.TypeXGlobalHeader:
			return nil, fmt.Errorf("unexptected tar file: (XGlobalHeader): type=%v name=%s", header.Typeflag, name)
		case tar.TypeXHeader:
			return nil, fmt.Errorf("unexptected tar file (XHeader): type=%v name=%s", header.Typeflag, name)
		default:
			files = append(files, &fs.FileData{
				Path:      filepath.Join("/", header.Name),
				Name:      filepath.Join("/", header.Name),
				Mod:       os.FileMode(header.Mode),
				ModStr:    os.FileMode(header.Mode).String(),
				ModTime:   header.ModTime,
				Change:    fs.ChangeDefault,
				Size:      header.Size,
				User:      fmt.Sprintf("%d", header.Uid),
				Group:     fmt.Sprintf("%d", header.Gid),
				LinkName:  header.Linkname,
				IsDir:     header.Typeflag == tar.TypeDir,
				IsSymlink: false,
			})
		}
	}
	return files, nil
}

func (self Client) ImageLoadFromOci(ctx context.Context, ociPath string, imageName string) error {
	srcRef, err := archive.NewReference(ociPath, "")
	if err != nil {
		return err
	}
	destRef, err := daemon.ParseReference(imageName)
	if err != nil {
		return err
	}

	policyContext, err := signature.NewPolicyContext(&signature.Policy{
		Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
	})
	if err != nil {
		return err
	}
	defer policyContext.Destroy()

	currentOS, currentArch := function.CurrentSystemPlatform()
	sysCtx := &types.SystemContext{
		ArchitectureChoice: currentArch,
		OSChoice:           currentOS,
		DockerDaemonHost:   self.Client.DaemonHost(),
	}

	_, err = imagecopy.Image(ctx, policyContext, destRef, srcRef, &imagecopy.Options{
		SourceCtx:      sysCtx,
		DestinationCtx: sysCtx,
	})

	return err
}
