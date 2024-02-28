/******************************************************************************
*
*  Copyright 2024 SAP SE
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
******************************************************************************/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/sapcc/go-bits/vault"
	"github.com/urfave/cli/v2"
)

type Result[T any] struct {
	value T
	err   error
}

type LimitedQueue[T any] struct {
	channel chan func()
}

func NewLimitedQueue[T any](ctx context.Context, concurrency int) LimitedQueue[T] {
	queue := LimitedQueue[T]{channel: make(chan func())}
	work := func() {
		for {
			select {
			case f := <-queue.channel:
				f()
			case <-ctx.Done():
				return
			}
		}
	}
	for range concurrency {
		go work()
	}
	return queue
}

func (queue *LimitedQueue[T]) Do(f func() (T, error)) (T, error) {
	out := make(chan Result[T])
	work := func() {
		val, err := f()
		result := Result[T]{value: val, err: err}
		out <- result
	}
	queue.channel <- work
	result := <-out
	return result.value, result.err
}

func main() {
	app := cli.App{
		Name:  "mutavault",
		Usage: "Additional utilities to interact with Hashicorp vault",
		Commands: []*cli.Command{
			{
				Name:  "kv",
				Usage: "Utilities for interacting with a kvv2 engine",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "mount",
						Usage:    "Mount path of kvv2 engine",
						Required: true,
					},
				},
				Subcommands: []*cli.Command{
					{
						Name:   "listall",
						Usage:  "List all accessible paths in a kv engine",
						Action: listall,
					},
					{
						Name:   "getcustommetas",
						Usage:  "Gets the custom metadata of provided paths to secrets",
						Args:   true,
						Action: getcustommetas,
					},
					{
						Name:   "setcustommetas",
						Usage:  "Takes custommetadata and paths on stdin and updates vault",
						Action: setcustommetas,
					},
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func listall(ctx *cli.Context) error {
	client, err := vault.CreateClient()
	if err != nil {
		return err
	}
	queue := NewLimitedQueue[*api.Secret](ctx.Context, 10)
	result, err := listSecretDirRecurse(ctx.Context, &queue, client, ctx.String("mount"), "/")
	if err != nil {
		return err
	}
	for _, path := range result {
		fmt.Println(path[1:])
	}
	return nil
}

// TODO: parallelize requests
func listSecretDirRecurse(ctx context.Context, queue *LimitedQueue[*api.Secret], client *api.Client, mount, path string) ([]string, error) {
	fmt.Print(".")
	subPaths, err := listSecretDir(ctx, queue, client, mount, path)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, subPath := range subPaths {
		next := path + subPath
		if !strings.HasSuffix(next, "/") {
			result = append(result, next)
			continue
		}
		subSecrets, err := listSecretDirRecurse(ctx, queue, client, mount, next)
		if err != nil {
			return nil, err
		}
		result = append(result, subSecrets...)
	}
	return result, nil
}

func listSecretDir(ctx context.Context, queue *LimitedQueue[*api.Secret], client *api.Client, mount, path string) ([]string, error) {
	data, err := queue.Do(func() (*api.Secret, error) {
		return client.Logical().ListWithContext(ctx, fmt.Sprintf("%s/metadata/%s", mount, path))
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list keys in %s: %w", path, err)
	}
	// at a leaf secret
	if data == nil {
		return []string{}, nil
	}
	interfaces, ok := data.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("secret metadata at %s did not contain the expected keys", path)
	}
	keys, err := interfaceSliceToStringSlice(interfaces)
	if err != nil {
		return nil, fmt.Errorf("retrieved secret keys that are not strings: %w", err)
	}
	return keys, nil
}

func interfaceSliceToStringSlice(s []interface{}) ([]string, error) {
	result := make([]string, 0)
	for _, val := range s {
		str, ok := val.(string)
		if !ok {
			return nil, errors.New("element is not a string")
		}
		result = append(result, str)
	}
	return result, nil
}

func getcustommetas(ctx *cli.Context) error {
	client, err := vault.CreateClient()
	if err != nil {
		return err
	}
	customMetas := make([]map[string]any, 0)
	for _, path := range ctx.Args().Slice() {
		meta, err := client.KVv2(ctx.String("mount")).GetMetadata(ctx.Context, path)
		if err != nil {
			return err
		}
		if meta.CustomMetadata == nil {
			meta.CustomMetadata = make(map[string]interface{})
		}
		meta.CustomMetadata["path"] = path
		customMetas = append(customMetas, meta.CustomMetadata)
	}
	return json.NewEncoder(os.Stdout).Encode(customMetas)
}

func setcustommetas(ctx *cli.Context) error {
	client, err := vault.CreateClient()
	if err != nil {
		return err
	}
	customMetas := make([]map[string]any, 0)
	if err = json.NewDecoder(os.Stdin).Decode(&customMetas); err != nil {
		return err
	}
	for _, customMeta := range customMetas {
		pathInterface, ok := customMeta["path"]
		if !ok {
			return errors.New("found object without path key")
		}
		path, ok := pathInterface.(string)
		if !ok {
			return errors.New("found object with non-string value for path")
		}
		delete(customMeta, "path")
		meta, err := client.KVv2(ctx.String("mount")).GetMetadata(ctx.Context, path)
		if err != nil {
			return err
		}
		if meta == nil {
			return fmt.Errorf("secret on path %s does not exist", path)
		}
		err = client.KVv2(ctx.String("mount")).PutMetadata(ctx.Context, path, api.KVMetadataPutInput{
			CustomMetadata: customMeta,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
