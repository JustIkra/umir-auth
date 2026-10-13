package domain

import (
	"errors"
	"slices"
)

var ErrAccessDenied = errors.New("auth scope access denied")

type RestaurantAccess struct {
	OrgID            EntityID `json:"orgID"`
	RestaurantID     EntityID `json:"restaurantID"`
	Roles            []string `json:"roles"`
	OrgRoles         []string `json:"orgRoles"`
	Permissions      []string `json:"permissions"`
	Settings         Settings `json:"settings"`
	LifecycleVersion Version  `json:"lifecycleVersion"`
}

var warehousePermissions = []string{"catalog.read", "catalog.write", "stock.read", "delivery.create", "analytics.read", "writeoff.confirm", "menu.read", "recommendations.read", "feedback.submit"}
var waiterPermissions = []string{"menu.read", "recommendations.read", "order.prepare", "order.confirm", "order.read", "feedback.submit"}
var adminPermissions = []string{"org.read", "org.settings.write", "restaurant.create", "restaurant.delete", "org.delete", "membership.manage", "invitation.manage", "org.summary.read", "feedback.read", "feedback.export"}

func IsOrgAdmin(a Aggregate, userID, orgID EntityID) bool {
	activeOrg := false
	for _, o := range a.Organizations {
		if o.OrgID == orgID && o.Lifecycle == "active" {
			activeOrg = true
			break
		}
	}
	if !activeOrg {
		return false
	}
	for _, m := range a.Memberships {
		if m.UserID == userID && m.OrgID == orgID && m.State == "active" && slices.Contains(m.OrgRoles, "Admin") {
			return true
		}
	}
	return false
}
func RestaurantPermissions(a Aggregate, userID, restaurantID EntityID) (RestaurantAccess, error) {
	var r Restaurant
	for _, candidate := range a.Restaurants {
		if candidate.RestaurantID == restaurantID {
			r = candidate
			break
		}
	}
	if r.RestaurantID == "" || r.Lifecycle != "ready" {
		return RestaurantAccess{}, ErrAccessDenied
	}
	var o Organization
	for _, candidate := range a.Organizations {
		if candidate.OrgID == r.OrgID {
			o = candidate
			break
		}
	}
	if o.OrgID == "" || o.Lifecycle != "active" {
		return RestaurantAccess{}, ErrAccessDenied
	}
	for _, m := range a.Memberships {
		if m.UserID != userID || m.OrgID != o.OrgID || m.State != "active" {
			continue
		}
		roles := []string{}
		orgRoles := slices.Clone(m.OrgRoles)
		admin := slices.Contains(orgRoles, "Admin")
		if admin {
			roles = []string{"Warehouse", "Waiter"}
		} else {
			for _, as := range m.Assignments {
				if as.RestaurantID == restaurantID {
					roles = slices.Clone(as.Roles)
					break
				}
			}
		}
		if len(roles) == 0 {
			return RestaurantAccess{}, ErrAccessDenied
		}
		permissions := []string{}
		add := func(values []string) {
			for _, p := range values {
				if !slices.Contains(permissions, p) {
					permissions = append(permissions, p)
				}
			}
		}
		if slices.Contains(roles, "Warehouse") {
			add(warehousePermissions)
		}
		if slices.Contains(roles, "Waiter") {
			add(waiterPermissions)
		}
		if admin {
			add(adminPermissions)
		}
		return RestaurantAccess{OrgID: o.OrgID, RestaurantID: r.RestaurantID, Roles: roles, OrgRoles: orgRoles, Permissions: permissions, Settings: o.Settings, LifecycleVersion: r.LifecycleVersion}, nil
	}
	return RestaurantAccess{}, ErrAccessDenied
}
