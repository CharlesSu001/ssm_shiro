/**
 * Copyright (C), 2015-2020, XXX有限公司
 * FileName: URLPathMatchingFilter
 * Author:   苏晨宇
 * Date:     2020/12/7 18:48
 * Description: url过滤器
 * History:
 * <author>          <time>          <version>          <desc>
 * 作者姓名           修改时间           版本号              描述
 */
package com.how2java.filter;

import com.how2java.service.PermissionService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * 〈一句话功能简述〉<br>
 * 〈url过滤器〉
 *
 * @author 苏晨宇
 * @create 2020/12/7
 * @since 1.0.0
 */
public class URLPathMatchingFilter extends PathMatchingFilter {
    @Autowired
    PermissionService permissionService;

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        String requestURI = getPathWithinApplication(request);

        System.out.println("requestURI:" + requestURI);
        Subject subject = SecurityUtils.getSubject();
        //如果没有登录，就跳转到登录页面
        if (!subject.isAuthenticated()) {
            WebUtils.issueRedirect(request, response, "/login");
            return false;
        }

        //看路径是否在维护 如果没有维护 一律放行
        boolean needInterceptor = permissionService.needInterceptor(requestURI);
        if (!needInterceptor) {
            return true;
        } else {
            boolean hasPermission = false;
            String userName = subject.getPrincipal().toString();
            Set<String> permissionUrls = permissionService.listPermissionURLs(userName);
            for (String url : permissionUrls) {
                //表示用户有这个权限
                if (url.equals(requestURI)) {
                    hasPermission = true;
                    break;
                }
            }

            if (hasPermission)
                return true;
            else {
                UnauthorizedException ex = new UnauthorizedException("当前用户没有访问路径" + requestURI + "的权限");
                subject.getSession().setAttribute("ex", ex);
                WebUtils.issueRedirect(request, response, "/unauthorized");
                return false;
            }
        }
    }

}
 
