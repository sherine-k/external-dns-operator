package externaldnscontroller

import (
	"context"
	"fmt"
	"strings"

	controller "github.com/openshift/external-dns-operator/pkg/operator/controller"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (r *reconciler) ensureOperatorRoleInExternalDNSNS(ctx context.Context, namespace string) (bool, *rbacv1.Role, error) {
	name := types.NamespacedName{
		Name:      controller.ServiceAccountName,
		Namespace: namespace,
	}

	desired := desiredOperatorRole(name)

	exists, current, err := r.currentOperatorRoleInExternalDNSNS(ctx, name)
	if err != nil {
		return false, nil, err
	}

	if !exists {
		if err := r.createOperatorRoleInExternalDNSNS(ctx, &desired); err != nil {
			return false, nil, err
		}
		return r.currentOperatorRoleInExternalDNSNS(ctx, name)
	}

	// update the cluster role
	if updated, err := r.updateOperatorRoleInExternalDNSNS(ctx, current, &desired); err != nil {
		return true, current, err
	} else if updated {
		return r.currentOperatorRoleInExternalDNSNS(ctx, name)
	}

	return true, current, nil
}

func (r *reconciler) ensureOperatorRoleBindingInExternalDNSNS(ctx context.Context, namespace string, operatorNamespace string) (bool, *rbacv1.RoleBinding, error) {
	name := types.NamespacedName{
		Name:      controller.ServiceAccountName,
		Namespace: namespace,
	}

	desired := desiredOperatorRoleBinding(name, operatorNamespace)

	exists, current, err := r.currentOperatorRoleBindingInExternalDNSNS(ctx, name)
	if err != nil {
		return false, nil, err
	}

	if !exists {
		if err := r.createOperatorRoleBindingInExternalDNSNS(ctx, desired); err != nil {
			return false, nil, err
		}
		return r.currentOperatorRoleBindingInExternalDNSNS(ctx, name)
	}

	// update the cluster role
	if updated, err := r.updateOperatorRoleBindingInExternalDNSNS(ctx, current, desired); err != nil {
		return true, current, err
	} else if updated {
		return r.currentOperatorRoleBindingInExternalDNSNS(ctx, name)
	}

	return true, current, nil
}

func desiredOperatorRole(name types.NamespacedName) rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		},
	}

	return rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		Rules: rules,
	}

}

func (r *reconciler) currentOperatorRoleInExternalDNSNS(ctx context.Context, name types.NamespacedName) (bool, *rbacv1.Role, error) {
	role := &rbacv1.Role{}
	if err := r.client.Get(ctx, name, role); err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, role, nil
}

func (r *reconciler) createOperatorRoleInExternalDNSNS(ctx context.Context, desired *rbacv1.Role) error {
	if err := r.client.Create(ctx, desired); err != nil {
		return fmt.Errorf("failed to create operator role %s in namespace %s: %w", desired.Name, desired.Namespace, err)
	}
	r.log.Info(
		"created operator role in operand namespace",
		"name",
		desired.Name,
		"namespace",
		desired.Namespace,
	)
	return nil
}

func (r *reconciler) updateOperatorRoleInExternalDNSNS(ctx context.Context, current, desired *rbacv1.Role) (bool, error) {
	changed, reason := rulesChanged(current.Rules, desired.Rules)
	if !changed {
		return false, nil
	}
	updated := current.DeepCopy()

	updated.Rules = desired.Rules
	if err := r.client.Update(ctx, updated); err != nil {
		return false, err
	}
	r.log.Info("updated operator role in operand namespace", "name", updated.Name, "namespace", updated.Namespace, "reason", reason)
	return true, nil
}

func desiredOperatorRoleBinding(name types.NamespacedName, operatorNamespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     name.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      controller.ServiceAccountName,
				Namespace: operatorNamespace,
			},
		},
	}
}

func (r *reconciler) currentOperatorRoleBindingInExternalDNSNS(ctx context.Context, name types.NamespacedName) (bool, *rbacv1.RoleBinding, error) {
	rb := &rbacv1.RoleBinding{}
	if err := r.client.Get(ctx, name, rb); err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, rb, nil
}

func (r *reconciler) createOperatorRoleBindingInExternalDNSNS(ctx context.Context, desired *rbacv1.RoleBinding) error {
	if err := r.client.Create(ctx, desired); err != nil {
		return fmt.Errorf("failed to create externalDNS operator role binding %s within namespace %s: %w", desired.Name, desired.Namespace, err)
	}
	r.log.Info("created externalDNS operator role binding in operand namespace", "name", desired.Name, "namespace", desired.Namespace)
	return nil
}

func (r *reconciler) updateOperatorRoleBindingInExternalDNSNS(ctx context.Context, current, desired *rbacv1.RoleBinding) (bool, error) {
	updated := current.DeepCopy()

	changed, reason := externalDNSRoleBindingChanged(current, desired, updated)
	if !changed {
		return false, nil
	}

	if err := r.client.Update(ctx, updated); err != nil {
		return false, err
	}
	r.log.Info("updated externalDNS operator role binding within operand namespace", "name", updated.Name, "namespace", updated.Namespace, "reason", reason)
	return true, nil
}

func externalDNSRoleBindingChanged(current, desired, updated *rbacv1.RoleBinding) (bool, string) {
	changed := false
	what := []string{}

	if current.RoleRef.Name != desired.RoleRef.Name {
		updated.RoleRef.Name = desired.RoleRef.Name
		changed = true
		what = append(what, "role-name")
	}

	if current.Subjects != nil && len(current.Subjects) > 0 {
		if current.Subjects[0].Name != desired.Subjects[0].Name {
			updated.Subjects[0].Name = desired.Subjects[0].Name
			changed = true
			what = append(what, "subject-name")
		}

		if current.Subjects[0].Namespace != desired.Subjects[0].Namespace {
			updated.Subjects[0].Namespace = desired.Subjects[0].Namespace
			changed = true
			what = append(what, "subject-namespace")
		}
	}
	return changed, fmt.Sprintf("following fields changed: %s", strings.Join(what, ","))

}
