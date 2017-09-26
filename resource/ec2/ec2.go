package ec2instance

/*  This file is part of AreBOT.

    AreBOT is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    AreBOT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AreBOT.  If not, see <http://www.gnu.org/licenses/>.
*/

import (
	"fmt"
	"os"
	"strings"
	"strconv"

	"github.com/kreuzwerker/arebot/config"
	"github.com/kreuzwerker/arebot/util"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/ec2"
)

var (
	// Log Logger for this package
	Log = newLogger()
	// Cfg Config for this package
	Cfg *config.Config
)

func newLogger() *logrus.Logger {
	_log := logrus.New()
	_log.Out = os.Stdout
	_log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	_log.Level = logrus.DebugLevel
	return _log
}

// EC2Error error definition
type EC2Error struct {
	id     string
	msg    string
	Ignore bool
}

func (e EC2Error) Error() string {
	return fmt.Sprintf("EC2 error %s: %s", e.id, e.msg)
}

// NewEC2Error create new EC2Error
func NewEC2Error(id, msg string, ignore bool) EC2Error {
	return EC2Error{id: id, msg: msg, Ignore: ignore}
}

type EC2inst struct {
	State  *ec2.Instance
}

type Volume struct {
	State *ec2.Volume
}

type Snapshot struct {
	State *ec2.Snapshot
}

// NewEC2 create a new EC2 object
func NewEC2(ec2out *ec2.Instance) EC2inst {
	e := EC2inst{}
	if ec2out == nil {
		ec2out = new(ec2.Instance)
	}

	e.State = ec2out
	return e
}

// NewEC2WithStatus create a new EC2 object including the current status of the AWS resource
func NewEC2WithStatus(eID string, accountID string) (EC2inst, error) {
	desc := NewEC2(nil)

	var reservation *ec2.Reservation
	var err error
	reservation, err = util.DescribeEC2ById(eID, accountID)

	if err != nil {
		Log.Errorf("ec2instance.NewEC2WithStatus: %s", err)
		return desc, NewEC2Error(eID, err.Error(), true)
	}

	desc.State = reservation.Instances[0]
	return desc, nil
}

// GetProperties returns the given properties for <key> argument
func (e *EC2inst) GetProperties(key string) []string {
	/*
		ImageId
		InstanceType
		Placement
			AvailabilityZone
			GroupName
			Tenancy
		PrivateIpAddress
		PublicIpAddress
		RootDeviceName
		RootDeviceType
		Tags
	*/
	var result []string

	splitKey := strings.Split(key, ".")
	Log.Debugf("EC2 Property keys: %+v", splitKey)

	switch splitKey[0] {
	case "ImageId":
		if imageId := e.State.ImageId; imageId != nil {
			Log.Debugf("EC2.GetProperties: Found ImageId: %s", fmt.Sprintf("%s", *imageId))
			result = append(result, *imageId)
		}
	case "InstanceType":
		if instanceType := e.State.InstanceType; instanceType != nil {
			Log.Debugf("EC2.GetProperties: Found InstanceType: %s", fmt.Sprintf("%s", *instanceType))
			result = append(result, *instanceType)
		}
	case "Placement":
		if len(splitKey) < 2 {
			return nil
		}
		switch splitKey[1] {
		case "AvailabilityZone":
			if az := e.State.Placement.AvailabilityZone; az != nil {
				Log.Debugf("EC2.GetProperties: Found Placement.AvailabilityZone: %s", fmt.Sprintf("%s", *az))
				result = append(result, *az)
			}
		case "GroupName":
			if gn := e.State.Placement.GroupName; gn != nil {
				Log.Debugf("EC2.GetProperties: Found Placement.GroupName: %s", fmt.Sprintf("%s", *gn))
				result = append(result, *gn)
			}
		case "Tenancy":
			if tenancy := e.State.Placement.Tenancy; tenancy != nil {
				Log.Debugf("EC2.GetProperties: Found Placement.Tenancy: %s", fmt.Sprintf("%s", *tenancy))
				result = append(result, *tenancy)
			}
		default:
			Log.Warnf("EC2.GetProperties: Configuration Placement.%s is not supported!", splitKey[1])
		}

	case "PrivateIpAddress":
		if pvtIPaddr := e.State.PrivateIpAddress; pvtIPaddr != nil {
			Log.Debugf("EC2.GetProperties: Found PrivateIpAddress: %s", fmt.Sprintf("%s", *pvtIPaddr))
			result = append(result, *pvtIPaddr)
		}
	case "PublicIpAddress":
		if pubIPaddr := e.State.PublicIpAddress; pubIPaddr != nil {
			Log.Debugf("EC2.GetProperties: Found PublicIpAddress: %s", fmt.Sprintf("%s", *pubIPaddr))
			result = append(result, *pubIPaddr)
		}
	case "RootDeviceName":
		if rootDevName := e.State.RootDeviceName; rootDevName != nil {
			Log.Debugf("EC2.GetProperties: Found RootDeviceName: %s", fmt.Sprintf("%s", *rootDevName))
			result = append(result, *rootDevName)
		}
	case "RootDeviceType":
		if rootDevType := e.State.RootDeviceType; rootDevType != nil {
			Log.Debugf("EC2.GetProperties: Found RootDeviceType: %s", fmt.Sprintf("%s", *rootDevType))
			result = append(result, *rootDevType)
		}
	case "Tag":
		for _, t := range e.State.Tags {
			if t.Key != nil && *t.Key == splitKey[1] {
				Log.Debugf("EC2.GetProperties: Found Tag: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Value":
		value := strings.Split(key, "Tag:Value.")
		for _, t := range e.State.Tags {
			if t.Value != nil && *t.Value == value[1] {
				Log.Debugf("EC2.GetProperties: Found Tag with Value: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Pair":
		value := strings.Split(key, "Tag:Pair.")
		pair := strings.Split(value[1], "---")
		for _, t := range e.State.Tags {
			if t.Key != nil && *t.Key == pair[0] && t.Value != nil && *t.Value == pair[1] {
				Log.Debugf("EC2.GetProperties: Found Tag with pair: `%s - %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	}

	return result
}

func (e *EC2inst) GetId() string {
	return *e.State.InstanceId
}

// NewVolume create a new Volume object
func NewVolume(volOut *ec2.Volume) Volume {
	vol := Volume{}
	if volOut == nil {
		volOut = new(ec2.Volume)
	}

	vol.State = volOut
	return vol
}

// NewVolumeWithStatus create a new Volume object including the current status of the AWS resource
func NewVolumeWithStatus(vID string, accountID string) (Volume, error) {
	desc := NewVolume(nil)

	state, err := util.DescribeVolumeById(vID, accountID)

	if err != nil {
		Log.Errorf("ec2instance.NewVolumeWithStatus: %s", err)
		return desc, NewEC2Error(vID, err.Error(), true)
	}

	desc.State = state
	return desc, nil
}

// GetProperties returns the given properties for <key> argument
func (vol *Volume) GetProperties(key string) []string {
	/*
		Attachments
			AttachTime
			DeleteOnTermination
			Device
			InstanceId
			State

		AvailabilityZone
		CreateTime
		Iops
		Size
		SnapshotId
		State
		Tags
		VolumeId
		VolumeType
	*/
	var result []string

	splitKey := strings.Split(key, ".")
	Log.Debugf("Volume Property keys: %+v", splitKey)

	switch splitKey[0] {
	case "Attachments":
		if len(splitKey) < 2 {
			return nil
		}
		for _, attach := range vol.State.Attachments {
			switch splitKey[1] {
				case "AttachTime":
					if at := attach.AttachTime; at != nil {
						Log.Debugf("Volume.GetProperties: Found Attachments.AttachTime: %s", fmt.Sprintf("%s", at.String()))
						result = append(result, at.String())
					}
				case "DeleteOnTermination":
					if dot := attach.DeleteOnTermination; dot != nil {
						sDot := strconv.FormatBool(*dot)
						Log.Debugf("Volume.GetProperties: Found Attachments.DeleteOnTermination: %s", fmt.Sprintf("%s", sDot))
						result = append(result,sDot)
					}
				case "Device":
					if device := attach.Device; device != nil {
						Log.Debugf("Volume.GetProperties: Found Attachments.Device: %s", fmt.Sprintf("%s", *device))
						result = append(result,*device)
					}
				case "InstanceId":
					if inst := attach.InstanceId; inst != nil {
						Log.Debugf("Volume.GetProperties: Found Attachments.InstanceId: %s", fmt.Sprintf("%s", *inst))
						result = append(result,*inst)
					}
				case "Status":
					if state := attach.State; state != nil {
						Log.Debugf("Volume.GetProperties: Found Attachments.Status: %s", fmt.Sprintf("%s", *state))

					}
			}
		}


	case "AvailabilityZone":
		if az := vol.State.AvailabilityZone; az != nil {
			Log.Debugf("Volume.GetProperties: Found AvailabilityZone: %s", fmt.Sprintf("%s", *az))
			result = append(result, *az)
		}
	case "CreateTime":
		if ct := vol.State.CreateTime; ct != nil {
			Log.Debugf("Volume.GetProperties: Found CreateTime: %s", fmt.Sprintf("%s", ct.String()))
			result = append(result, ct.String())
		}
	case "Iops":
		if iops := vol.State.Iops; iops != nil {
			sIops := strconv.FormatInt(*iops, 10)
			Log.Debugf("Volume.GetProperties: Found Iops: %s", fmt.Sprintf("%s", sIops))
			result = append(result,sIops)
		}
	case "Size":
		if size := vol.State.Size; size != nil {
			sSize := strconv.FormatInt(*size, 10)
			Log.Debugf("Volume.GetProperties: Found Size: %s", fmt.Sprintf("%s", sSize))
			result = append(result,sSize)
		}
	case "SnapshotId":
		if snapId := vol.State.SnapshotId; snapId != nil {
			Log.Debugf("Volume.GetProperties: Found SnapshotId: %s", fmt.Sprintf("%s", *snapId))
			result = append(result, *snapId)
		}
	case "Status":
		if state := vol.State.State; state != nil {
			Log.Debugf("Volume.GetProperties: Found Status: %s", fmt.Sprintf("%s", *state))
			result = append(result, *state)
		}
	case "Tag":
		for _, t := range vol.State.Tags {
			if t.Key != nil && *t.Key == splitKey[1] {
				Log.Debugf("Volume.GetProperties: Found Tag: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Value":
		value := strings.Split(key, "Tag:Value.")
		for _, t := range vol.State.Tags {
			if t.Value != nil && *t.Value == value[1] {
				Log.Debugf("Volume.GetProperties: Found Tag with Value: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Pair":
		value := strings.Split(key, "Tag:Pair.")
		pair := strings.Split(value[1], "---")
		for _, t := range vol.State.Tags {
			if t.Key != nil && *t.Key == pair[0] && t.Value != nil && *t.Value == pair[1] {
				Log.Debugf("Volume.GetProperties: Found Tag with pair: `%s - %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "VolumeType":
		if volType := vol.State.VolumeType; volType != nil {
			Log.Debugf("Volume.GetProperties: Found VolumeType: %s", fmt.Sprintf("%s", *volType))
			result = append(result, *volType)
		}
	}

	return result
}

func (v *Volume) GetId() string {
	return *v.State.VolumeId
}

// NewSnapshot create a new Snapshot object
func NewSnapshot(snap *ec2.Snapshot) Snapshot {
	s := Snapshot{ State: snap }
	return s
}

// NewSnapshotWithStatus create a new Snapshot object including the current status of the AWS resource
func NewSnapshotWithStatus(snapId string, accountID string) (Snapshot, error) {
	desc := NewSnapshot(nil)

	state, err := util.DescribeSnapshotById(snapId, accountID)

	if err != nil {
		Log.Errorf("ec2instance.NewSnapshotWithStatus: %s", err)
		return desc, NewEC2Error(snapId, err.Error(), true)
	}

	desc.State = state
	return desc, nil
}

// GetProperties returns the given properties for <key> argument
func (snap *Snapshot) GetProperties(key string) []string {
	/*
		Description
		Encrypted
		OwnerAlias
		OwnerId
		StartTime
		State
		Tags
		VolumeId
		VolumeSize
	*/
	var result []string

	splitKey := strings.Split(key, ".")
	Log.Debugf("Snapshot Property keys: %+v", splitKey)

	switch splitKey[0] {
	case "Description":
		if desc := snap.State.Description; desc != nil {
			Log.Debugf("Snapshot.GetProperties: Found Description: %s", fmt.Sprintf("%s", *desc))
			result = append(result, *desc)
		}
	case "StartTime":
		if st := snap.State.StartTime; st != nil {
			Log.Debugf("Snapshot.GetProperties: Found StartTime: %s", fmt.Sprintf("%s", st.String()))
			result = append(result, st.String())
		}
	case "Encrypted":
		if enc := snap.State.Encrypted; enc != nil {
			sEnc := strconv.FormatBool(*enc)
			Log.Debugf("Snapshot.GetProperties: Found Encrypted: %s", fmt.Sprintf("%s", sEnc))
			result = append(result,sEnc)
		}
	case "VolumeSize":
		if vsize := snap.State.VolumeSize; vsize != nil {
			sVsize := strconv.FormatInt(*vsize, 10)
			Log.Debugf("Snapshot.GetProperties: Found VolumeSize: %s", fmt.Sprintf("%s", sVsize))
			result = append(result,sVsize)
		}
	case "VolumeId":
		if volId := snap.State.VolumeId; volId != nil {
			Log.Debugf("Snapshot.GetProperties: Found VolumeId: %s", fmt.Sprintf("%s", *volId))
			result = append(result, *volId)
		}
	case "Status":
		if state := snap.State.State; state != nil {
			Log.Debugf("Snapshot.GetProperties: Found Status: %s", fmt.Sprintf("%s", *state))
			result = append(result, *state)
		}
	case "OwnerAlias":
		if ownAlias := snap.State.OwnerAlias; ownAlias != nil {
			Log.Debugf("Snapshot.GetProperties: Found OwnerAlias: %s", fmt.Sprintf("%s", *ownAlias))
			result = append(result, *ownAlias)
		}
	case "OwnerId":
		if ownId := snap.State.OwnerId; ownId != nil {
			Log.Debugf("Snapshot.GetProperties: Found OwnerId: %s", fmt.Sprintf("%s", *ownId))
			result = append(result, *ownId)
		}
	case "Tag":
		for _, t := range snap.State.Tags {
			if t.Key != nil && *t.Key == splitKey[1] {
				Log.Debugf("Snapshot.GetProperties: Found Tag: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Value":
		value := strings.Split(key, "Tag:Value.")
		for _, t := range snap.State.Tags {
			if t.Value != nil && *t.Value == value[1] {
				Log.Debugf("Snapshot.GetProperties: Found Tag with Value: `%s: %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	case "Tag:Pair":
		value := strings.Split(key, "Tag:Pair.")
		pair := strings.Split(value[1], "---")
		for _, t := range snap.State.Tags {
			if t.Key != nil && *t.Key == pair[0] && t.Value != nil && *t.Value == pair[1] {
				Log.Debugf("Snapshot.GetProperties: Found Tag with pair: `%s - %s`", *t.Key, *t.Value)
				result = append(result, *t.Value)
			}
		}
	}

	return result
}

func (s *Snapshot) GetId() string {
	return *s.State.SnapshotId
}
