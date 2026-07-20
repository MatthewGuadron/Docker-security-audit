/*
© AngelaMos | 2026
container.go

ContainerAnalyzer inspects live running containers via the Docker API

Fetches the full inspect response for each container and checks CIS
Section 5 controls: privileged mode, dangerous capabilities, Docker
socket and sensitive path mounts, host network/PID/IPC/UTS namespace
sharing, seccomp and AppArmor profiles, no-new-privileges flag, and
memory/CPU/PIDs resource limits.

Key exports:
  ContainerAnalyzer - implements Analyzer for live containers
  NewContainerAnalyzer - constructor taking a docker.Client

Connects to:
  analyzer.go - implements Analyzer interface, uses Category constants
  docker/client.go - lists and inspects containers
  rules/capabilities.go - classifies cap_add entries
  rules/paths.go - identifies sensitive and socket mounts
  benchmark/controls.go - fetches CIS control metadata for each finding
  finding.go - creates findings with CISControl references
*/

package analyzer

import (
	"context"
	"strconv"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/docker"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/rules"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

type ContainerAnalyzer struct {
	client *docker.Client
}

func NewContainerAnalyzer(client *docker.Client) *ContainerAnalyzer {
	return &ContainerAnalyzer{client: client}
}

func (a *ContainerAnalyzer) Name() string {
	return "container"
}

func (a *ContainerAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	containers, err := a.client.ListContainers(ctx, true)
	if err != nil {
		return nil, err
	}

	var findings finding.Collection
	for _, c := range containers {
		info, err := a.client.InspectContainer(ctx, c.ID)
		if err != nil {
			continue
		}
		findings = append(findings, a.analyzeContainer(info)...)
	}

	return findings, nil
}

func (a *ContainerAnalyzer) analyzeContainer(
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection
	target := finding.Target{
		Type: finding.TargetContainer,
		Name: strings.TrimPrefix(info.Name, "/"),
		ID:   info.ID,
	}

	if info.HostConfig == nil {
		return findings
	}

	findings = append(findings, a.checkPrivileged(target, info)...)
	findings = append(findings, a.checkResourceLimits(target, info)...)
	findings = append(findings, a.checkExposedPorts(target, info)...)
	findings = append(findings, a.checkCapabilities(target, info)...)
	findings = append(findings, a.checkMounts(target, info)...)
	findings = append(findings, a.checkImageTag(target, info)...)
	findings = append(findings, a.checkNamespaces(target, info)...)
	findings = append(findings, a.checkSecurityOptions(target, info)...)
	findings = append(findings, a.checkReadonlyRootfs(target, info)...)

	return findings
}

func (a *ContainerAnalyzer) checkPrivileged(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.4")
		f := finding.New("CIS-5.4", control.Title, finding.SeverityCritical, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkCapabilities(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	for _, cap := range info.HostConfig.CapAdd {
		capName := strings.ToUpper(string(cap))
		capInfo, exists := rules.GetCapabilityInfo(capName)
		if !exists {
			continue
		}

		if capInfo.Severity >= finding.SeverityHigh {
			control, _ := benchmark.Get("5.3")
			title := "Dangerous capability added: " + capName
			if capInfo.Severity == finding.SeverityCritical {
				title = "Critical capability added: " + capName
			}
			f := finding.New("CIS-5.3", title, capInfo.Severity, target).
				WithDescription(capInfo.Description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ContainerAnalyzer) checkMounts(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	addMountFinding := func(source string) {
		if source == "" {
			return
		}

		if rules.IsDockerSocket(source) {
			control, _ := benchmark.Get("5.31")
			pathInfo, _ := rules.GetPathInfo(source)

			description := "Mounting Docker socket gives the container full control over the Docker daemon."
			if pathInfo.Description != "" {
				description = pathInfo.Description
			}

			f := finding.New("CIS-5.31", control.Title, finding.SeverityCritical, target).
				WithDescription(description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())

			findings = append(findings, f)
			return
		}

		if rules.IsSensitivePath(source) {
			control, _ := benchmark.Get("5.5")
			pathInfo, _ := rules.GetPathInfo(source)
			severity := rules.GetPathSeverity(source)

			description := control.Description
			if pathInfo.Description != "" {
				description = pathInfo.Description
			}

			f := finding.New("CIS-5.5", "Sensitive host path mounted: "+source, severity, target).
				WithDescription(description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())

			findings = append(findings, f)
		}
	}

	// Docker inspect may include parsed mounts here.
	for _, mount := range info.Mounts {
		addMountFinding(mount.Source)
	}

	// The test fixtures and some inspect outputs store bind mounts here.
	for _, bind := range info.HostConfig.Binds {
		parts := strings.SplitN(bind, ":", 2)
		if len(parts) > 0 {
			addMountFinding(parts[0])
		}
	}

	return findings
}

func (a *ContainerAnalyzer) checkNamespaces(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig.NetworkMode == "host" {
		control, _ := benchmark.Get("5.9")
		f := finding.New("CIS-5.9", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.PidMode == "host" {
		control, _ := benchmark.Get("5.15")
		f := finding.New("CIS-5.15", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.IpcMode == "host" {
		control, _ := benchmark.Get("5.16")
		f := finding.New("CIS-5.16", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.UTSMode == "host" {
		control, _ := benchmark.Get("5.20")
		f := finding.New("CIS-5.20", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkSecurityOptions(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	hasAppArmor := false
	hasSeccomp := false
	hasNoNewPrivileges := false
	seccompDisabled := false

	for _, opt := range info.HostConfig.SecurityOpt {
		if strings.HasPrefix(opt, "apparmor=") {
			hasAppArmor = true
		}
		if strings.HasPrefix(opt, "seccomp=") {
			hasSeccomp = true
			if opt == "seccomp=unconfined" {
				seccompDisabled = true
			}
		}
		if opt == "no-new-privileges" || opt == "no-new-privileges:true" {
			hasNoNewPrivileges = true
		}
	}

	if !hasAppArmor && !info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.1")
		f := finding.New("CIS-5.1", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if seccompDisabled {
		control, _ := benchmark.Get("5.21")
		f := finding.New("CIS-5.21", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if !hasSeccomp && !info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.21")
		f := finding.New("CIS-5.21", "No seccomp profile set", finding.SeverityMedium, target).
			WithDescription("Container is running without an explicit seccomp profile. While Docker applies a default profile, it's recommended to explicitly set one.").
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if !hasNoNewPrivileges {
		control, _ := benchmark.Get("5.25")
		f := finding.New("CIS-5.25", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkImageTag(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	if info.Config == nil {
		return nil
	}

	image := info.Config.Image

	// Digest-pinned images are safer, so do not flag them.
	if strings.Contains(image, "@sha256:") {
		return nil
	}

	// Docker treats "nginx" as "nginx:latest", so no tag should also be flagged.
	if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
		control, _ := benchmark.Get("5.27")

		f := finding.New("CIS-5.27", "Container uses latest image tag", finding.SeverityMedium, target).
			WithDescription("Using the latest tag makes the container image version unpredictable and can introduce unreviewed changes.").
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation("Use a specific version tag or digest, such as nginx:1.27 or nginx@sha256:<digest>.").
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())

		return finding.Collection{f}
	}

	return nil
}

func (a *ContainerAnalyzer) checkExposedPorts(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	if info.NetworkSettings == nil {
		return findings
	}

	if info.NetworkSettings.Ports == nil {
		return findings
	}

	for containerPort, bindings := range info.NetworkSettings.Ports {
		portParts := strings.Split(string(containerPort), "/")
		if len(portParts) == 0 {
			continue
		}

		portNumber, err := strconv.Atoi(portParts[0])
		if err != nil {
			continue
		}

		serviceName, sensitive := rules.SensitivePorts[portNumber]
		if !sensitive {
			continue
		}

		for _, binding := range bindings {
			if binding.HostIP == "" || binding.HostIP == "0.0.0.0" || binding.HostIP == "::" {
				title := "Sensitive port exposed to all interfaces: " + serviceName

				remediation := "Bind sensitive ports to localhost only or restrict access with firewall rules."
				if binding.HostPort != "" {
					remediation = "Bind sensitive ports to localhost only, such as 127.0.0.1:" + binding.HostPort + ":" + portParts[0] + ", or restrict access with firewall rules."
				}

				f := finding.New("DS-EXPOSED-PORT", title, finding.SeverityHigh, target).
					WithDescription("Container exposes sensitive service port " + portParts[0] + " (" + serviceName + ") to all network interfaces.").
					WithCategory(string(CategoryContainerRuntime)).
					WithRemediation(remediation)

				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (a *ContainerAnalyzer) checkResourceLimits(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig == nil {
		return findings
	}

	hostConfig := info.HostConfig

	if hostConfig.Memory == 0 {
		control, _ := benchmark.Get("5.10")

		f := finding.New(
			"CIS-5.10",
			control.Title,
			finding.SeverityMedium,
			target,
		).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())

		findings = append(findings, f)
	}

	if hostConfig.NanoCPUs == 0 &&
		hostConfig.CPUShares == 0 &&
		hostConfig.CPUQuota == 0 &&
		hostConfig.CPUPeriod == 0 {
		control, _ := benchmark.Get("5.11")

		f := finding.New(
			"CIS-5.11",
			control.Title,
			finding.SeverityMedium,
			target,
		).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())

		findings = append(findings, f)
	}

	if hostConfig.PidsLimit == nil || *hostConfig.PidsLimit <= 0 {
		control, _ := benchmark.Get("5.28")

		f := finding.New(
			"CIS-5.28",
			control.Title,
			finding.SeverityMedium,
			target,
		).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())

		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkReadonlyRootfs(
	target finding.Target,
	info container.InspectResponse,
) finding.Collection {
	var findings finding.Collection

	if !info.HostConfig.ReadonlyRootfs {
		control, _ := benchmark.Get("5.12")
		f := finding.New("CIS-5.12", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}
