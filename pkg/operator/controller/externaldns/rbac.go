/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package externaldnscontroller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
	operatorv1alpha1 "github.com/openshift/external-dns-operator/api/v1alpha1"
	controller "github.com/openshift/external-dns-operator/pkg/operator/controller"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ensureExternalDNSClusterRole ensures that the externalDNS cluster role exists.
// Returns a boolean if the cluster role exists, its current state if it exists
// and an error if it cannot be created or updated.
func (r *reconciler) ensureExternalDNSClusterRole(ctx context.Context, externalDNS *operatorv1alpha1.ExternalDNS) (bool, *rbacv1.ClusterRole, error) {
	name := types.NamespacedName{Name: controller.ExternalDNSGlobalResourceName()}

	desired := desiredExternalDNSClusterRole(externalDNS)

	exists, current, err := r.currentExternalDNSClusterRole(ctx, name)
	if err != nil {
		return false, nil, err
	}

	if !exists {
		if err := r.createExternalDNSClusterRole(ctx, desired); err != nil {
			return false, nil, err
		}
		return r.currentExternalDNSClusterRole(ctx, name)
	}

	// update the cluster role
	if updated, err := r.updateExternalDNSClusterRole(ctx, current, desired); err != nil {
		return true, current, err
	} else if updated {
		return r.currentExternalDNSClusterRole(ctx, name)
	}

	return true, current, nil
}

// ensureExternalDNSClusterRoleBinding ensures that externalDNS cluster role binding exists.
// Returns a boolean if the cluster role binding exists, and an error when relevant.
func (r *reconciler) ensureExternalDNSClusterRoleBinding(ctx context.Context, namespace string, externalDNS *operatorv1alpha1.ExternalDNS) (bool, *rbacv1.ClusterRoleBinding, error) {
	name := types.NamespacedName{Name: controller.ExternalDNSResourceName(externalDNS)}
	crbName := types.NamespacedName{Name: controller.ExternalDNSBaseName}

	currentSAs, err := r.currentExtDNSOwnedServiceAccounts(ctx, namespace)
	if err != nil {
		return false, nil, err
	}
	desired := desiredExternalDNSClusterRoleBinding(namespace, externalDNS, currentSAs)

	exists, current, err := r.currentExternalDNSClusterRoleBinding(ctx, crbName)
	if err != nil {
		return false, nil, err
	}

	if !exists {
		if err := r.createExternalDNSClusterRoleBinding(ctx, desired); err != nil {
			return false, nil, err
		}
		return r.currentExternalDNSClusterRoleBinding(ctx, name)
	}

	if updated, err := r.updateExternalDNSClusterRoleBinding(ctx, current, desired); err != nil {
		return true, current, err
	} else if updated {
		return r.currentExternalDNSClusterRoleBinding(ctx, name)
	}

	return true, current, nil
}

// desiredExternalDNSClusterRole returns the desired cluster role definition for externalDNS
func desiredExternalDNSClusterRole(externalDNS *operatorv1alpha1.ExternalDNS) *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"networking.k8s.io"},
			Resources: []string{"ingresses"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints", "services", "pods", "nodes"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}

	if externalDNS.Spec.Source.Type == operatorv1alpha1.SourceTypeRoute {
		rule := rbacv1.PolicyRule{
			APIGroups: []string{"route.openshift.io"},
			Resources: []string{"routes"},
			Verbs:     []string{"get", "watch", "list"},
		}
		rules = append(rules, rule)
	}

	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ExternalDNSBaseName,
		},
		Rules: rules,
	}
}

// desiredExternalDNSClusterRoleBinding returns the desired cluster role binding's definition for externalDNS
func desiredExternalDNSClusterRoleBinding(namespace string, externalDNS *operatorv1alpha1.ExternalDNS, sasOwnedByExtDNS []string) *rbacv1.ClusterRoleBinding {
	rb:= &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ExternalDNSBaseName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     controller.ExternalDNSBaseName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      controller.ExternalDNSResourceName(externalDNS),
				Namespace: namespace,
			},
		},
	}
	for _,sa := range(sasOwnedByExtDNS){
		if sa != controller.ExternalDNSResourceName(externalDNS){
			subject := rbacv1.Subject{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      sa,
					Namespace: namespace,
				}
			rb.Subjects = append(rb.Subjects, subject)
		}
	}
	return rb
}

// currentExternalDNSClusterRole returns true if cluster role exists
func (r *reconciler) currentExternalDNSClusterRole(ctx context.Context, name types.NamespacedName) (bool, *rbacv1.ClusterRole, error) {
	cr := &rbacv1.ClusterRole{}
	if err := r.client.Get(ctx, name, cr); err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, cr, nil
}

// currentExternalDNSClusterRoleBinding returns true if cluster role binding exists
func (r *reconciler) currentExternalDNSClusterRoleBinding(ctx context.Context, name types.NamespacedName) (bool, *rbacv1.ClusterRoleBinding, error) {
	crb := &rbacv1.ClusterRoleBinding{}
	if err := r.client.Get(ctx, name, crb); err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, crb, nil
}


func (r *reconciler) currentExtDNSOwnedServiceAccounts (ctx context.Context, namespace string) ([]string, error){
	serviceAccounts := &corev1.ServiceAccountList {}
	matchingSANames := []string{}
	if err := r.client.List(ctx, serviceAccounts, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	for _, sa := range (serviceAccounts.Items){
		for _, ownerRef := range(sa.GetObjectMeta().GetOwnerReferences()){
			if ownerRef.Kind == "ExternalDNS"{
				matchingSANames = append(matchingSANames, sa.Name)
			}
		}
	}
	return matchingSANames, nil
}
// createExternalDNSClusterRole creates the given cluster role
func (r *reconciler) createExternalDNSClusterRole(ctx context.Context, desired *rbacv1.ClusterRole) error {
	if err := r.client.Create(ctx, desired); err != nil {
		return fmt.Errorf("failed to create externalDNS cluster role %s: %w", desired.Name, err)
	}
	r.log.Info("created externalDNS cluster role", "name", desired.Name)
	return nil
}

// createExternalDNSClusterRoleBinding creates the given cluster role binding
func (r *reconciler) createExternalDNSClusterRoleBinding(ctx context.Context, desired *rbacv1.ClusterRoleBinding) error {
	if err := r.client.Create(ctx, desired); err != nil {
		return fmt.Errorf("failed to create externalDNS cluster role binding %s: %w", desired.Name, err)
	}
	r.log.Info("created externalDNS cluster role binding", "name", desired.Name)
	return nil
}

// updateExternalDNSClusterRole updates the cluster role with the desired state if the rules differ
func (r *reconciler) updateExternalDNSClusterRole(ctx context.Context, current, desired *rbacv1.ClusterRole) (bool, error) {
	changed, reason := externalDNSRoleRulesChanged(current.Rules, desired.Rules)
	if !changed {
		return false, nil
	}

	updated := current.DeepCopy()
	// no complicated resets of specific rules are used
	// if there is change: reset all
	updated.Rules = desired.Rules
	if err := r.client.Update(ctx, updated); err != nil {
		return false, err
	}
	r.log.Info("updated externalDNS cluster role", "name", updated.Name, "reason", reason)
	return true, nil
}

// updateExternalDNSClusterRoleBinding updates the cluster role binding with the desired state if the role or subject changed
func (r *reconciler) updateExternalDNSClusterRoleBinding(ctx context.Context, current, desired *rbacv1.ClusterRoleBinding) (bool, error) {
	updated := current.DeepCopy()

	changed, reason := externalDNSRoleBindingChanged(current, desired, updated)
	if !changed {
		return false, nil
	}

	if err := r.client.Update(ctx, updated); err != nil {
		return false, err
	}
	r.log.Info("updated externalDNS cluster role binding", "name", updated.Name, "reason", reason)
	return true, nil
}

// externalDNSRoleRulesChanged returns true if the contents of the rules changed.
// The order of apigroups, resources, and verbs does not matter.
func externalDNSRoleRulesChanged(current, expected []rbacv1.PolicyRule) (bool, string) {
	currentRuleMap := buildSortedPolicyRuleMap(current)
	expectedRuleMap := buildSortedPolicyRuleMap(expected)

	if diff := cmp.Diff(expectedRuleMap, currentRuleMap); diff != "" {
		return true, fmt.Sprintf("diff found in the policy rules: %s", diff)
	}

	return false, ""
}

// externalDNSRoleBindingChanged returns true if the role binding changed,
// second output value is the reason of the change (role/subject).
// Updated input parameter is set with the desired values in case the role binding changed.
func externalDNSRoleBindingChanged(current, desired, updated *rbacv1.ClusterRoleBinding) (bool, string) {
	changed := false
	what := []string{}

	if current.RoleRef.Name != desired.RoleRef.Name {
		updated.RoleRef.Name = desired.RoleRef.Name
		changed = true
		what = append(what, "role-name")
	}

	if current.Subjects != nil && len(current.Subjects) > 0 {
		currentSubjects := make(map[string]rbacv1.Subject)
		for _,subject := range(current.Subjects){
			currentSubjects[subject.Name+"-"+subject.Namespace] = subject
		}
		for _,desiredSubject := range(desired.Subjects){
			if _, found := currentSubjects[desiredSubject.Name+"-"+desiredSubject.Namespace]; !found{
				changed = true
				what = append(what, "subject: "+ desiredSubject.Name+", Namespace: "+desiredSubject.Namespace)
			}
		}
	}

	return changed, fmt.Sprintf("following fields changed: %s", strings.Join(what, ","))
}

// buildSortedPolicyRuleMap creates a map of policy rules
// key: "apigroup/resource"
// value: list of verbs
func buildSortedPolicyRuleMap(rules []rbacv1.PolicyRule) map[string][]string {
	m := map[string][]string{}
	for _, rule := range rules {
		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				sortedVerbs := make([]string, len(rule.Verbs))
				copy(sortedVerbs, rule.Verbs)
				sort.Strings(sortedVerbs)
				m[apiGroup+"/"+resource] = sortedVerbs
			}
		}
	}
	return m
}
