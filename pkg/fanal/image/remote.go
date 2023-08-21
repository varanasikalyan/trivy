package image

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/remote"
)

func tryRemote(ctx context.Context, imageName string, ref name.Reference, option types.RegistryOptions) (types.Image, error) {
	desc, err := remote.Get(ctx, ref, option)
	if err != nil {
		return nil, err
	}
	fmt.Printf("** Manifest: %s\n", desc.MediaType)
	if desc.MediaType == "application/vnd.oci.image.index.v1+json" || desc.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		fmt.Printf("** List Manifest\n")
		imageManifest, err := v1.ParseIndexManifest(bytes.NewReader(desc.Manifest))
		if err != nil {
			return nil, err
		}
		for _, val := range imageManifest.Manifests {
			fmt.Printf("** Arch: %s, OS: %s, Variant: %s\n", val.Platform.Architecture, val.Platform.OS, val.Platform.Variant)
		}
	} else if desc.MediaType == "application/vnd.oci.image.manifest.v1+json" || desc.MediaType == "application/vnd.docker.distribution.manifest.v2+json" {
		fmt.Printf("** Schema2 Manifest\n")
		fmt.Printf("** Arch: %s, OS: %s, Variant: %s\n", desc.Platform.Architecture, desc.Platform.OS, desc.Platform.Variant)
	} else {
		fmt.Printf("** Schema1 Manifest or Unexpected media type for Image()\n")
	}
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	// Return v1.Image if the image is found in Docker Registry
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, nil

}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *remote.Descriptor
	v1.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	return ID(img)
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

type implicitReference struct {
	ref name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()

	// Default registry
	if reg != name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}

	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}
